using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;

namespace UploadGuard.ClamAV;

/// <summary>Rejects uploads that clamd flags. Registered by <c>AddUploadGuardClamAV</c>.</summary>
internal sealed partial class ClamAVScanner(ClamAVClient client, ILogger<ClamAVScanner> logger) : IUploadScanner
{
    public async Task ScanAsync(Stream content, FileType type, CancellationToken cancellationToken)
    {
        var result = await client.ScanAsync(content, cancellationToken);
        if (result.IsInfected)
        {
            // The signature goes to the log, not to the client: it would help an attacker tune the payload.
            LogInfected(logger, result.Signature, type.Name);
            throw new UploadRejectedException(new(UploadErrorCode.Malware, "The file contains malware."));
        }
    }

    [LoggerMessage(1, LogLevel.Warning, "ClamAV found {Signature} in an uploaded {FileType}")]
    private static partial void LogInfected(ILogger logger, string? signature, string fileType);
}

/// <summary>Healthy when clamd answers PING.</summary>
internal sealed class ClamAVHealthCheck(ClamAVClient client) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            return await client.PingAsync(cancellationToken)
                ? HealthCheckResult.Healthy()
                : new HealthCheckResult(context.Registration.FailureStatus, "clamd did not answer PONG.");
        }
        catch (Exception e) when (e is IOException or System.Net.Sockets.SocketException or TimeoutException or ClamAVException)
        {
            return new HealthCheckResult(context.Registration.FailureStatus, "clamd is unreachable.", e);
        }
    }
}
