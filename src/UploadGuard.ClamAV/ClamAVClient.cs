using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace UploadGuard.ClamAV;

/// <summary>Where clamd listens.</summary>
public sealed class ClamAVOptions
{
    /// <summary>Gets or sets the host name or IP address. Defaults to <c>localhost</c>.</summary>
    public string Host { get; set; } = "localhost";

    /// <summary>Gets or sets the TCP port. Defaults to 3310.</summary>
    public int Port { get; set; } = 3310;

    /// <summary>Gets or sets how long one command may take, including the upload of the content. Defaults to 30 seconds.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>The verdict for one scan.</summary>
/// <param name="IsInfected">Whether clamd found a signature.</param>
/// <param name="Signature">The signature name, for example <c>Win.Test.EICAR_HDB-1</c>, when infected.</param>
public sealed record ClamAVScanResult(bool IsInfected, string? Signature);

/// <summary>clamd answered with an error, for example when the content exceeds its <c>StreamMaxLength</c>.</summary>
public sealed class ClamAVException : Exception
{
    /// <summary>Initializes a new instance.</summary>
    public ClamAVException()
    {
    }

    /// <summary>Initializes a new instance with clamd's reply.</summary>
    /// <param name="message">The reply.</param>
    public ClamAVException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with clamd's reply and the cause.</summary>
    /// <param name="message">The reply.</param>
    /// <param name="innerException">The cause.</param>
    public ClamAVException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// An async client for the clamd TCP protocol. Each call opens its own connection, so one instance is safe to share.
/// </summary>
/// <param name="options">The connection settings.</param>
public sealed class ClamAVClient(ClamAVOptions options)
{
    private const int ChunkSize = 64 * 1024;
    private const int MaxReplyLength = 4096;

    private readonly ClamAVOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Checks that clamd is up.</summary>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>True when clamd answers <c>PONG</c>.</returns>
    public async Task<bool> PingAsync(CancellationToken cancellationToken = default) =>
        await SendAsync("PING", null, cancellationToken) == "PONG";

    /// <summary>Gets the engine and signature database version.</summary>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>For example <c>ClamAV 1.4.1/27445/Mon Nov  2 09:25:00 2026</c>.</returns>
    public Task<string> GetVersionAsync(CancellationToken cancellationToken = default) =>
        SendAsync("VERSION", null, cancellationToken);

    /// <summary>Streams content to clamd with <c>INSTREAM</c> and returns the verdict.</summary>
    /// <param name="content">The content, read from its current position to the end.</param>
    /// <param name="cancellationToken">Cancels the scan.</param>
    /// <returns>The verdict.</returns>
    /// <exception cref="ClamAVException">clamd reported an error.</exception>
    /// <exception cref="TimeoutException">clamd did not answer within <see cref="ClamAVOptions.Timeout"/>.</exception>
    public async Task<ClamAVScanResult> ScanAsync(Stream content, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        var reply = await SendAsync("INSTREAM", content, cancellationToken);

        // "stream: OK", "stream: <signature> FOUND" or "<reason> ERROR".
        const string Prefix = "stream: ";
        if (reply == Prefix + "OK")
        {
            return new(false, null);
        }

        if (reply.StartsWith(Prefix, StringComparison.Ordinal) && reply.EndsWith(" FOUND", StringComparison.Ordinal))
        {
            return new(true, reply[Prefix.Length..^" FOUND".Length]);
        }

        throw new ClamAVException($"clamd: {reply}");
    }

    private async Task<string> SendAsync(string command, Stream? content, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Timeout);
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(_options.Host, _options.Port, timeout.Token);
            var network = tcp.GetStream();
            await network.WriteAsync(Encoding.ASCII.GetBytes($"z{command}\0"), timeout.Token);
            if (content is not null)
            {
                try
                {
                    await StreamChunksAsync(content, network, timeout.Token);
                }
                catch (IOException)
                {
                    // clamd closes the connection when the content exceeds StreamMaxLength; its reply says so.
                }
            }

            return await ReadReplyAsync(network, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"clamd at {_options.Host}:{_options.Port} did not answer within {_options.Timeout}.");
        }
    }

    // INSTREAM: chunks prefixed with their length as a 4-byte big-endian integer, ended by a zero-length chunk.
    private static async Task StreamChunksAsync(Stream content, NetworkStream network, CancellationToken cancellationToken)
    {
        var buffer = new byte[4 + ChunkSize];
        int read;
        while ((read = await content.ReadAsync(buffer.AsMemory(4, ChunkSize), cancellationToken)) > 0)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)read);
            await network.WriteAsync(buffer.AsMemory(0, 4 + read), cancellationToken);
        }

        await network.WriteAsync(new byte[4], cancellationToken);
    }

    // The "z" command prefix makes clamd end its reply with a NUL byte.
    private static async Task<string> ReadReplyAsync(NetworkStream network, CancellationToken cancellationToken)
    {
        var reply = new byte[MaxReplyLength];
        var length = 0;
        while (length < reply.Length)
        {
            var read = await network.ReadAsync(reply.AsMemory(length), cancellationToken);
            if (read == 0)
            {
                break;
            }

            length += read;
            if (reply.AsSpan(0, length).Contains((byte)0))
            {
                break;
            }
        }

        var text = Encoding.ASCII.GetString(reply, 0, length);
        var end = text.IndexOf('\0', StringComparison.Ordinal);
        return (end >= 0 ? text[..end] : text).Trim();
    }
}
