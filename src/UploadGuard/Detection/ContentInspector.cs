using System.Text;

namespace UploadGuard.Detection;

/// <summary>Type-specific checks that run once the type is known and allowed.</summary>
internal static class ContentInspector
{
    private static readonly HashSet<FileType> ZipBased =
    [
        FileTypes.Zip, FileTypes.Docx, FileTypes.Docm, FileTypes.Xlsx, FileTypes.Xlsm, FileTypes.Pptx, FileTypes.Pptm,
        FileTypes.Odt, FileTypes.Ods, FileTypes.Odp,
    ];

    // Polyglots: an image that is also an HTML page or a PHP script. Long patterns keep false positives near zero.
    private static readonly byte[][] ImageMarkup =
        ["<script"u8.ToArray(), "<?php"u8.ToArray(), "<html"u8.ToArray(), "<iframe"u8.ToArray(), "<body"u8.ToArray(), "javascript:"u8.ToArray()];

    // The directory entry of a VBA project in a Compound File (UTF-16LE): "_VBA_PROJECT" and "_VBA_PROJECT_CUR".
    // A byte search, not a CFB parser; PowerPoint 97 can store VBA elsewhere. Antivirus covers the rest.
    private static readonly byte[][] OleMacros = [Encoding.Unicode.GetBytes("_VBA_PROJECT")];

    public static async Task<UploadError?> InspectAsync(Stream stream, FileType type, UploadPolicy policy, CancellationToken cancellationToken)
    {
        if (ZipBased.Contains(type))
        {
            return await ArchiveInspector.CheckZipAsync(stream, type, policy, cancellationToken);
        }

        if (type == FileTypes.Gzip)
        {
            return await ArchiveInspector.CheckGzipAsync(stream, policy, cancellationToken);
        }

        if (type == FileTypes.Pdf)
        {
            return await PdfInspector.CheckAsync(stream, policy, cancellationToken);
        }

        if (type == FileTypes.Svg)
        {
            return await SvgInspector.CheckAsync(stream, cancellationToken);
        }

        if (type == FileTypes.Doc || type == FileTypes.Xls || type == FileTypes.Ppt)
        {
            stream.Position = 0;
            return await ByteScanner.FindFirstAsync(stream, OleMacros, ScanMode.Exact, cancellationToken) >= 0
                ? new(UploadErrorCode.ActiveContent, "The document contains macros.")
                : null;
        }

        if (type.MimeType.StartsWith("image/", StringComparison.Ordinal))
        {
            stream.Position = 0;
            return await ByteScanner.FindFirstAsync(stream, ImageMarkup, ScanMode.IgnoreCase, cancellationToken) >= 0
                ? new(UploadErrorCode.ActiveContent, "The image contains embedded script or HTML.")
                : null;
        }

        return null;
    }
}
