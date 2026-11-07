namespace UploadGuard;

/// <summary>UploadGuard configuration: named policies and the default storage folder.</summary>
public sealed class UploadGuardOptions
{
    internal Dictionary<string, UploadPolicy> Policies { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the folder where <see cref="UploadPipeline.SaveAsync(Microsoft.AspNetCore.Http.IFormFile, string, CancellationToken)"/>
    /// stores files with <see cref="FileSystemUploadStorage"/>. It must be outside the web root. Leave it null to
    /// register your own <see cref="IUploadStorage"/> or to only validate.
    /// </summary>
    public string? StoragePath { get; set; }

    /// <summary>Adds a named policy.</summary>
    /// <param name="name">The name used by <c>WithUploadPolicy</c>, <c>[UploadPolicy]</c> and <see cref="UploadPipeline"/>.</param>
    /// <param name="configure">Configures the policy; it must allow at least one type.</param>
    /// <returns>These options.</returns>
    /// <exception cref="ArgumentException">A policy with this name already exists.</exception>
    /// <exception cref="InvalidOperationException">The policy allows no file types.</exception>
    public UploadGuardOptions AddPolicy(string name, Action<UploadPolicy> configure)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(configure);
        var policy = new UploadPolicy();
        configure(policy);
        if (policy.AllowedTypes.Count == 0)
        {
            throw new InvalidOperationException($"Upload policy '{name}' allows no file types. Call Allow or AllowImages.");
        }

        Policies.Add(name, policy);
        return this;
    }
}
