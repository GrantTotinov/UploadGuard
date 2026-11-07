using MimeDetective;
using MimeDetective.Definitions;
using UploadGuard.Tests;

namespace UploadGuard.Benchmarks;

/// <summary>
/// How a typical app uses each library: accept the upload when the detected extension equals the file's extension.
/// UploadGuard is used through a policy that allows the claimed type. Each returns what it detected, or null.
/// </summary>
internal static class Detectors
{
    private static readonly IContentInspector MimeInspector = new ContentInspectorBuilder { Definitions = DefaultDefinitions.All() }.Build();

    public static (bool Accepted, string? Detected) MimeDetective(byte[] data, string name)
    {
        var matches = MimeInspector.Inspect(data).ByFileExtension();
        var accepted = matches.Any(m => string.Equals(m.Extension, Extension(name), StringComparison.OrdinalIgnoreCase));
        return (accepted, matches.IsEmpty ? null : matches[0].Extension);
    }

    public static (bool Accepted, string? Detected) FileTypeChecker(byte[] data, string name)
    {
        using var stream = new MemoryStream(data);
        var detected = global::FileTypeChecker.FileTypeValidator.IsTypeRecognizable(stream)
            ? global::FileTypeChecker.FileTypeValidator.GetFileType(stream).Extension
            : null;
        return (string.Equals(detected, Extension(name), StringComparison.OrdinalIgnoreCase), detected);
    }

    public static (bool Accepted, string? Detected) UploadGuard(byte[] data, string name)
    {
        var extension = Path.GetExtension(name).ToLowerInvariant();
        var claimed = Samples.All.Keys.First(t => t.Extensions.Contains(extension));
        var pipeline = new UploadPipeline(new UploadGuardOptions().AddPolicy("p", p => p.Allow(claimed)));
        var result = pipeline.ValidateAsync(new MemoryStream(data), name, null, "p").GetAwaiter().GetResult();
        return (result.IsValid, result.Error?.Code.ToString() ?? result.FileType?.Extensions[0].TrimStart('.'));
    }

    private static string Extension(string name) => Path.GetExtension(name).TrimStart('.');
}
