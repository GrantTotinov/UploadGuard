using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using UploadGuard;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers UploadGuard.</summary>
public static class UploadGuardServiceCollectionExtensions
{
    /// <summary>Registers <see cref="UploadPipeline"/> with these policies, and file storage when <see cref="UploadGuardOptions.StoragePath"/> is set.</summary>
    /// <param name="services">The services.</param>
    /// <param name="configure">Adds policies, for example <c>o.AddPolicy("avatars", p => p.AllowImages().MaxSize(5_000_000))</c>.</param>
    /// <returns>The services.</returns>
    public static IServiceCollection AddUploadGuard(this IServiceCollection services, Action<UploadGuardOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        // Configured eagerly so a broken policy fails at startup, not on the first upload.
        var options = new UploadGuardOptions();
        configure(options);
        services.AddSingleton(options);
        services.TryAddSingleton<UploadPipeline>();
        if (options.StoragePath is { } path)
        {
            services.TryAddSingleton<IUploadStorage>(sp => FileSystemUploadStorage.Create(path, sp.GetService<IWebHostEnvironment>()?.WebRootPath));
        }

        return services;
    }
}
