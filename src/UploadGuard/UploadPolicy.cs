namespace UploadGuard;

/// <summary>
/// What one kind of upload may contain. Configure it in <see cref="UploadGuardOptions.AddPolicy"/>.
/// Everything not allowed is rejected; content checks always run.
/// </summary>
public sealed class UploadPolicy
{
    internal HashSet<FileType> AllowedTypes { get; } = [];

    internal long MaxSizeBytes { get; private set; } = 10 * 1024 * 1024;

    internal int MaxArchiveEntries { get; private set; } = 10_000;

    internal long MaxUncompressedBytes { get; private set; } = 256L * 1024 * 1024;

    internal int MaxCompressionRatio { get; private set; } = 100;

    internal List<IUploadTransformer> Transformers { get; } = [];

    /// <summary>Allows these types. The extension must belong to the detected type.</summary>
    /// <param name="types">Types from <see cref="FileTypes"/>.</param>
    /// <returns>This policy.</returns>
    public UploadPolicy Allow(params FileType[] types)
    {
        ArgumentNullException.ThrowIfNull(types);
        foreach (var type in types)
        {
            AllowedTypes.Add(type ?? throw new ArgumentException("Types cannot be null.", nameof(types)));
        }

        return this;
    }

    /// <summary>Allows the raster formats every browser shows: JPEG, PNG, GIF and WebP.</summary>
    /// <returns>This policy.</returns>
    public UploadPolicy AllowImages() => Allow(FileTypes.Jpeg, FileTypes.Png, FileTypes.Gif, FileTypes.Webp);

    /// <summary>Sets the maximum file size. Defaults to 10 MB. Also raise Kestrel's and the form's limits if needed.</summary>
    /// <param name="bytes">The limit in bytes.</param>
    /// <returns>This policy.</returns>
    public UploadPolicy MaxSize(long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytes);
        MaxSizeBytes = bytes;
        return this;
    }

    /// <summary>Sets the zip bomb limits for ZIP, GZIP, Office and OpenDocument files.</summary>
    /// <param name="maxEntries">The maximum number of entries. Defaults to 10,000.</param>
    /// <param name="maxUncompressedSize">The maximum total unpacked size in bytes. Defaults to 256 MB. Also caps how much PDF stream data is inflated for inspection.</param>
    /// <param name="maxCompressionRatio">The maximum unpacked size divided by the file size. Defaults to 100.</param>
    /// <returns>This policy.</returns>
    public UploadPolicy LimitArchives(int maxEntries = 10_000, long maxUncompressedSize = 256L * 1024 * 1024, int maxCompressionRatio = 100)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEntries);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxUncompressedSize);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxCompressionRatio);
        MaxArchiveEntries = maxEntries;
        MaxUncompressedBytes = maxUncompressedSize;
        MaxCompressionRatio = maxCompressionRatio;
        return this;
    }

    /// <summary>Adds a transform that runs on accepted files before <see cref="UploadPipeline.SaveAsync(Microsoft.AspNetCore.Http.IFormFile, string, CancellationToken)"/> stores them.</summary>
    /// <param name="transformer">The transform, for example image re-encoding from UploadGuard.PixelForge.</param>
    /// <returns>This policy.</returns>
    public UploadPolicy Transform(IUploadTransformer transformer)
    {
        ArgumentNullException.ThrowIfNull(transformer);
        Transformers.Add(transformer);
        return this;
    }
}
