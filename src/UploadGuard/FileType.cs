namespace UploadGuard;

/// <summary>A file format that UploadGuard recognizes by its content. All instances are in <see cref="FileTypes"/>.</summary>
public sealed class FileType
{
    internal FileType(string name, string[] extensions, string[] mimeTypes)
    {
        Name = name;
        Extensions = extensions;
        MimeTypes = mimeTypes;
    }

    /// <summary>Gets a display name, for example "JPEG image".</summary>
    public string Name { get; }

    /// <summary>Gets the lowercase file extensions, with the dot. The first one is used for stored files.</summary>
    public IReadOnlyList<string> Extensions { get; }

    /// <summary>Gets the Content-Type values that clients send for this type. The first one is canonical.</summary>
    public IReadOnlyList<string> MimeTypes { get; }

    /// <summary>Gets the canonical media type, for example <c>image/jpeg</c>.</summary>
    public string MimeType => MimeTypes[0];

    /// <inheritdoc />
    public override string ToString() => Name;
}
