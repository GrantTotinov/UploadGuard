using System.IO.Compression;

namespace UploadGuard.Detection;

/// <summary>ZIP-based formats (ZIP, Office Open XML, OpenDocument) and GZIP.</summary>
internal static class ArchiveInspector
{
    private const int MaxContentTypesChars = 1024 * 1024;

    /// <summary>Tells ZIP, DOCX/XLSX/PPTX (with or without macros) and ODT/ODS/ODP apart.</summary>
    public static async Task<FileType[]> DetectAsync(Stream stream, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        try
        {
            await using var zip = await ZipArchive.CreateAsync(stream, ZipArchiveMode.Read, leaveOpen: true, entryNameEncoding: null, cancellationToken);
            if (zip.GetEntry("[Content_Types].xml") is { } contentTypes)
            {
                return [DetectOffice(zip, await ReadTextAsync(contentTypes, MaxContentTypesChars, cancellationToken))];
            }

            if (zip.Entries is [{ FullName: "mimetype" } mimetype, ..])
            {
                return (await ReadTextAsync(mimetype, 100, cancellationToken)).Trim() switch
                {
                    "application/vnd.oasis.opendocument.text" => [FileTypes.Odt],
                    "application/vnd.oasis.opendocument.spreadsheet" => [FileTypes.Ods],
                    "application/vnd.oasis.opendocument.presentation" => [FileTypes.Odp],
                    _ => [FileTypes.Zip],
                };
            }
        }
        catch (Exception e) when (e is InvalidDataException or NotSupportedException)
        {
            // Damaged or encrypted: CheckZipAsync reports why.
        }

        return [FileTypes.Zip];
    }

    // Office decides by the main part's content type, so UploadGuard does too. A VBA project anywhere makes it macro-enabled.
    private static FileType DetectOffice(ZipArchive zip, string contentTypes)
    {
        bool Has(string value) => contentTypes.Contains(value, StringComparison.OrdinalIgnoreCase);
        var macros = Has("macroEnabled") || Has("vbaProject")
            || zip.Entries.Any(e => e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase));

        if (Has("wordprocessingml.document.main+xml") || Has("ms-word.document.macroEnabled.main+xml"))
        {
            return macros ? FileTypes.Docm : FileTypes.Docx;
        }

        if (Has("spreadsheetml.sheet.main+xml") || Has("ms-excel.sheet.macroEnabled.main+xml"))
        {
            return macros ? FileTypes.Xlsm : FileTypes.Xlsx;
        }

        if (Has("presentationml.presentation.main+xml") || Has("ms-powerpoint.presentation.macroEnabled.main+xml"))
        {
            return macros ? FileTypes.Pptm : FileTypes.Pptx;
        }

        return FileTypes.Zip;
    }

    private static async Task<string> ReadTextAsync(ZipArchiveEntry entry, int maxChars, CancellationToken cancellationToken)
    {
        await using var stream = await entry.OpenAsync(cancellationToken);
        using var reader = new StreamReader(stream);
        var buffer = new char[(int)Math.Min(entry.Length, maxChars)];
        var read = await reader.ReadBlockAsync(buffer, cancellationToken);
        return new string(buffer, 0, read);
    }

    /// <summary>Zip bomb limits, encryption and zip slip, from the central directory. Nothing is unpacked.</summary>
    /// <remarks>
    /// The sizes are the declared ones. .NET's ZipArchive never inflates an entry past its declared size, and other
    /// extractors fail on the CRC/size mismatch, so a lying size cannot hide a bomb from code that uses these sizes.
    /// </remarks>
    public static async Task<UploadError?> CheckZipAsync(Stream stream, FileType type, UploadPolicy policy, CancellationToken cancellationToken)
    {
        var openDocument = type == FileTypes.Odt || type == FileTypes.Ods || type == FileTypes.Odp;
        stream.Position = 0;
        try
        {
            // ZipArchive reads the whole central directory before we can count it. MaxSize bounds that
            // (about MaxSize / 46 entries); parse the end-of-central-directory record first if that ever matters.
            await using var zip = await ZipArchive.CreateAsync(stream, ZipArchiveMode.Read, leaveOpen: true, entryNameEncoding: null, cancellationToken);
            if (zip.Entries.Count > policy.MaxArchiveEntries)
            {
                return TooLarge($"The archive has {zip.Entries.Count} entries; the limit is {policy.MaxArchiveEntries}.");
            }

            long total = 0;
            foreach (var entry in zip.Entries)
            {
                if (entry.IsEncrypted)
                {
                    return new(UploadErrorCode.UnsafeArchive, "The archive has encrypted entries, which cannot be inspected or scanned.");
                }

                if (!IsSafePath(entry.FullName))
                {
                    return new(UploadErrorCode.UnsafeArchive, "The archive has an entry whose path leaves the extraction folder.");
                }

                if (openDocument && (entry.FullName.StartsWith("Basic/", StringComparison.OrdinalIgnoreCase)
                    || entry.FullName.StartsWith("Scripts/", StringComparison.OrdinalIgnoreCase)))
                {
                    return new(UploadErrorCode.ActiveContent, "The document contains macros.");
                }

                if (entry.Length > policy.MaxUncompressedBytes - total)
                {
                    return TooLarge($"The archive unpacks to more than {policy.MaxUncompressedBytes} bytes.");
                }

                total += entry.Length;
            }

            return total > policy.MaxCompressionRatio * stream.Length
                ? TooLarge($"The archive unpacks to more than {policy.MaxCompressionRatio} times its size.")
                : null;
        }
        catch (InvalidDataException)
        {
            return new(UploadErrorCode.Corrupt, "The archive is damaged.");
        }
    }

    /// <summary>Unpacks the whole GZIP stream without keeping it, stopping at the limit.</summary>
    public static async Task<UploadError?> CheckGzipAsync(Stream stream, UploadPolicy policy, CancellationToken cancellationToken)
    {
        var limit = Math.Min(policy.MaxUncompressedBytes, policy.MaxCompressionRatio * stream.Length);
        stream.Position = 0;
        try
        {
            await using var gzip = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await gzip.ReadAsync(buffer, cancellationToken)) > 0)
            {
                total += read;
                if (total > limit)
                {
                    return TooLarge($"The archive unpacks to more than {limit} bytes.");
                }
            }

            return null;
        }
        catch (InvalidDataException)
        {
            return new(UploadErrorCode.Corrupt, "The archive is damaged.");
        }
    }

    // Zip slip: absolute paths, drive letters and ".." segments, with either slash.
    internal static bool IsSafePath(string name)
    {
        var path = name.Replace('\\', '/');
        if (path.StartsWith('/') || path.Contains(':', StringComparison.Ordinal) || path.Contains('\0', StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var segment in path.Split('/'))
        {
            if (segment == "..")
            {
                return false;
            }
        }

        return true;
    }

    private static UploadError TooLarge(string message) => new(UploadErrorCode.ArchiveTooLarge, message);
}
