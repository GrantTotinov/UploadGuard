using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using UploadGuard.ClamAV;

namespace UploadGuard.Tests;

public sealed class ClamAVTests : IAsyncDisposable
{
    private readonly FakeClamd _clamd = new();

    public ValueTask DisposeAsync() => _clamd.DisposeAsync();

    [Fact]
    public async Task Ping_and_version()
    {
        var client = Client(_clamd.Port);

        Assert.True(await client.PingAsync(TestContext.Current.CancellationToken));
        Assert.StartsWith("ClamAV ", await client.GetVersionAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Instream_sends_the_whole_content_in_chunks()
    {
        var content = new byte[300_000];
        new Random(7).NextBytes(content);

        var result = await Client(_clamd.Port).ScanAsync(new MemoryStream(content), TestContext.Current.CancellationToken);

        Assert.False(result.IsInfected);
        Assert.Equal(content, _clamd.Received);
    }

    [Fact]
    public async Task Infected_content_reports_the_signature()
    {
        var result = await Client(_clamd.Port).ScanAsync(new MemoryStream(Samples.Eicar()), TestContext.Current.CancellationToken);

        Assert.Equal(new ClamAVScanResult(true, "Eicar-Signature"), result);
    }

    [Fact]
    public async Task Error_reply_throws()
    {
        _clamd.InstreamReply = "INSTREAM size limit exceeded. ERROR";

        var e = await Assert.ThrowsAsync<ClamAVException>(() => Client(_clamd.Port).ScanAsync(new MemoryStream([1]), TestContext.Current.CancellationToken));
        Assert.Contains("size limit", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Slow_clamd_times_out()
    {
        _clamd.Delay = TimeSpan.FromSeconds(5);
        var client = new ClamAVClient(new ClamAVOptions { Port = _clamd.Port, Host = "127.0.0.1", Timeout = TimeSpan.FromMilliseconds(200) });

        await Assert.ThrowsAsync<TimeoutException>(() => client.PingAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Pipeline_rejects_malware_and_keeps_clean_files()
    {
        await using var services = Services(_clamd.Port);
        var pipeline = services.GetRequiredService<UploadPipeline>();

        var infected = await pipeline.ValidateAsync(new MemoryStream(Samples.Eicar()), "eicar.txt", "text/plain", "docs", TestContext.Current.CancellationToken);
        var clean = await pipeline.ValidateAsync(new MemoryStream(Samples.Utf8("hello")), "hello.txt", "text/plain", "docs", TestContext.Current.CancellationToken);

        Assert.Equal(new UploadError(UploadErrorCode.Malware, "The file contains malware."), infected.Error);
        Assert.True(clean.IsValid);
    }

    [Fact]
    public async Task Pipeline_fails_closed_when_clamd_is_down()
    {
        await using var services = Services(ClosedPort());
        var pipeline = services.GetRequiredService<UploadPipeline>();

        var result = await pipeline.ValidateAsync(new MemoryStream(Samples.Utf8("hello")), "hello.txt", null, "docs", TestContext.Current.CancellationToken);

        Assert.Equal(UploadErrorCode.ScanFailed, result.Error?.Code);
    }

    [Fact]
    public async Task Health_check_follows_clamd()
    {
        await using var up = Services(_clamd.Port);
        await using var down = Services(ClosedPort());

        var healthy = await up.GetRequiredService<HealthCheckService>().CheckHealthAsync(TestContext.Current.CancellationToken);
        var unhealthy = await down.GetRequiredService<HealthCheckService>().CheckHealthAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HealthStatus.Healthy, healthy.Status);
        Assert.Equal(HealthStatus.Unhealthy, unhealthy.Status);
    }

    /// <summary>Runs against a real clamd when CLAMAV_HOST is set (CI starts one as a service container).</summary>
    [Fact]
    public async Task Real_clamd_detects_eicar()
    {
        var host = Environment.GetEnvironmentVariable("CLAMAV_HOST");
        if (string.IsNullOrEmpty(host))
        {
            Assert.Skip("Set CLAMAV_HOST to run against a real clamd.");
        }

        var client = new ClamAVClient(new ClamAVOptions { Host = host, Timeout = TimeSpan.FromMinutes(1) });

        Assert.True(await client.PingAsync(TestContext.Current.CancellationToken));
        Assert.True((await client.ScanAsync(new MemoryStream(Samples.Eicar()), TestContext.Current.CancellationToken)).IsInfected);
        Assert.False((await client.ScanAsync(new MemoryStream(Samples.Jpeg()), TestContext.Current.CancellationToken)).IsInfected);
    }

    private static ClamAVClient Client(int port) => new(new ClamAVOptions { Host = "127.0.0.1", Port = port });

    private static ServiceProvider Services(int port)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddUploadGuard(o => o.AddPolicy("docs", p => p.Allow(FileTypes.Text)));
        services.AddUploadGuardClamAV(o =>
        {
            o.Host = "127.0.0.1";
            o.Port = port;
            o.Timeout = TimeSpan.FromSeconds(5);
        });
        services.AddHealthChecks().AddClamAV();
        return services.BuildServiceProvider();
    }

    private static int ClosedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>Speaks enough of the clamd protocol to test the client: zPING, zVERSION and zINSTREAM.</summary>
    private sealed class FakeClamd : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;

        public FakeClamd()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _loop = Task.Run(AcceptAsync);
        }

        public int Port { get; }

        public byte[]? Received { get; private set; }

        public string? InstreamReply { get; set; }

        public TimeSpan Delay { get; set; }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _listener.Stop();
            await _loop;
            _stop.Dispose();
        }

        private async Task AcceptAsync()
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stop.Token);
                }
                catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException)
                {
                    return;
                }

                _ = HandleAsync(client);
            }
        }

        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                var stream = client.GetStream();
                var command = new StringBuilder();
                var one = new byte[1];
                while (await stream.ReadAsync(one) == 1 && one[0] != 0)
                {
                    command.Append((char)one[0]);
                }

                var reply = command.ToString() switch
                {
                    "zPING" => "PONG",
                    "zVERSION" => "ClamAV 1.4.1/27445/Fake",
                    "zINSTREAM" => await InstreamAsync(stream),
                    _ => "UNKNOWN COMMAND",
                };

                if (Delay > TimeSpan.Zero)
                {
                    await Task.Delay(Delay, _stop.Token).ContinueWith(_ => { }, TaskScheduler.Default);
                }

                await stream.WriteAsync(Encoding.ASCII.GetBytes(reply + "\0"));
            }
        }

        private async Task<string> InstreamAsync(NetworkStream stream)
        {
            var content = new MemoryStream();
            var length = new byte[4];
            while (true)
            {
                await stream.ReadExactlyAsync(length);
                var size = BinaryPrimitives.ReadInt32BigEndian(length);
                if (size == 0)
                {
                    break;
                }

                var chunk = new byte[size];
                await stream.ReadExactlyAsync(chunk);
                content.Write(chunk);
            }

            Received = content.ToArray();
            return InstreamReply
                ?? (Received.AsSpan().IndexOf("EICAR-STANDARD"u8) >= 0 ? "stream: Eicar-Signature FOUND" : "stream: OK");
        }
    }
}
