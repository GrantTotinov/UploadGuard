using UploadGuard;
using UploadGuard.ClamAV;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers the ClamAV scanner.</summary>
public static class ClamAVServiceCollectionExtensions
{
    /// <summary>
    /// Scans every upload that passes the built-in checks with clamd. Infected files are rejected with
    /// <see cref="UploadErrorCode.Malware"/>; when clamd is down or slow they are rejected with <see cref="UploadErrorCode.ScanFailed"/>.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <param name="configure">Sets the host, port and timeout, for example from configuration.</param>
    /// <returns>The services.</returns>
    public static IServiceCollection AddUploadGuardClamAV(this IServiceCollection services, Action<ClamAVOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = new ClamAVOptions();
        configure?.Invoke(options);
        services.AddSingleton(new ClamAVClient(options));
        services.AddSingleton<IUploadScanner, ClamAVScanner>();
        return services;
    }

    /// <summary>Adds a health check that pings clamd. Requires <see cref="AddUploadGuardClamAV"/>.</summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="name">The check name.</param>
    /// <param name="tags">Tags, for example <c>["ready"]</c>.</param>
    /// <returns>The builder.</returns>
    public static IHealthChecksBuilder AddClamAV(this IHealthChecksBuilder builder, string name = "clamav", IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddCheck<ClamAVHealthCheck>(name, tags: tags);
    }
}
