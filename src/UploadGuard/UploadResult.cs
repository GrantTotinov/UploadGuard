namespace UploadGuard;

/// <summary>Why an upload was rejected.</summary>
public enum UploadErrorCode
{
    /// <summary>The file has no content.</summary>
    Empty,

    /// <summary>The file, or the image it decodes to, is larger than the policy allows.</summary>
    TooLarge,

    /// <summary>The file name is empty, too long, has a path, control or bidi characters, or a dangerous inner extension.</summary>
    InvalidFileName,

    /// <summary>The content does not match any type UploadGuard knows.</summary>
    UnknownType,

    /// <summary>The extension does not belong to the detected type.</summary>
    ExtensionMismatch,

    /// <summary>The detected type is not in the policy's allow-list.</summary>
    TypeNotAllowed,

    /// <summary>The Content-Type header names a different type than the content.</summary>
    ContentTypeMismatch,

    /// <summary>Macros, PDF JavaScript, SVG scripts, or script markup inside an image.</summary>
    ActiveContent,

    /// <summary>The archive has too many entries, unpacks to too many bytes, or compresses too well.</summary>
    ArchiveTooLarge,

    /// <summary>The archive has encrypted entries or paths that escape the extraction folder.</summary>
    UnsafeArchive,

    /// <summary>The file structure is damaged and cannot be inspected.</summary>
    Corrupt,

    /// <summary>A scanner found malware.</summary>
    Malware,

    /// <summary>A scanner failed or timed out. Uploads fail closed.</summary>
    ScanFailed,
}

/// <summary>A rejection reason. The message is safe to return to the client.</summary>
/// <param name="Code">The machine-readable reason.</param>
/// <param name="Message">A human-readable explanation without internal details.</param>
public sealed record UploadError(UploadErrorCode Code, string Message);

/// <summary>The outcome of validating or saving one file.</summary>
public sealed record UploadResult
{
    /// <summary>Gets the file name the client sent. Display it, never use it as a path.</summary>
    public required string FileName { get; init; }

    /// <summary>Gets the size in bytes. After a transform, the size of the transformed content.</summary>
    public required long Length { get; init; }

    /// <summary>Gets the detected type, when detection got that far. After a transform, the output type.</summary>
    public FileType? FileType { get; init; }

    /// <summary>Gets why the file was rejected, or null when it was accepted.</summary>
    public UploadError? Error { get; init; }

    /// <summary>Gets the generated storage name after <see cref="UploadPipeline.SaveAsync(Microsoft.AspNetCore.Http.IFormFile, string, CancellationToken)"/>.</summary>
    public string? StoredName { get; init; }

    /// <summary>Gets a value indicating whether the file was accepted.</summary>
    public bool IsValid => Error is null;
}

/// <summary>Thrown by an <see cref="IUploadScanner"/> or <see cref="IUploadTransformer"/> to reject a file.</summary>
public sealed class UploadRejectedException : Exception
{
    /// <summary>Initializes a new instance with the rejection reason.</summary>
    /// <param name="error">The reason returned to the client.</param>
    public UploadRejectedException(UploadError error)
        : base(error?.Message) => Error = error ?? throw new ArgumentNullException(nameof(error));

    /// <summary>Gets the reason returned to the client.</summary>
    public UploadError Error { get; }
}
