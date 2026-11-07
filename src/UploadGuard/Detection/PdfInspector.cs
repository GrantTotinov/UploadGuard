using System.IO.Compression;

namespace UploadGuard.Detection;

/// <summary>Finds PDF features that act when the file is opened: JavaScript, launch actions, embedded files, XFA, rich media.</summary>
/// <remarks>
/// A byte scan, not a PDF parser. It decodes <c>#xx</c> name escapes and inflates FlateDecode streams
/// (object streams hide dictionaries since PDF 1.5), but not other filters such as LZW or ASCIIHex. Antivirus and
/// never rendering PDFs from users inline are the real backstop; a parser-based check can replace this later.
/// </remarks>
internal static class PdfInspector
{
    private static readonly (string Pattern, string What)[] Features =
    [
        ("/JavaScript", "JavaScript"),
        ("/JS ", "JavaScript"), ("/JS(", "JavaScript"), ("/JS<", "JavaScript"), ("/JS/", "JavaScript"),
        ("/JS[", "JavaScript"), ("/JS\r", "JavaScript"), ("/JS\n", "JavaScript"), ("/JS\t", "JavaScript"),
        ("/Launch", "a launch action"),
        ("/EmbeddedFile", "embedded files"),
        ("/RichMedia", "rich media"),
        ("/XFA", "an XFA form"),
    ];

    private static readonly byte[][] Patterns = [.. Features.Select(f => System.Text.Encoding.ASCII.GetBytes(f.Pattern))];
    private static readonly byte[][] StreamKeyword = ["stream"u8.ToArray()];

    public static async Task<UploadError?> CheckAsync(Stream stream, UploadPolicy policy, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        var found = await ByteScanner.FindFirstAsync(stream, Patterns, ScanMode.PdfNames, cancellationToken);
        if (found >= 0)
        {
            return Active(found);
        }

        var streams = new List<long>();
        stream.Position = 0;
        await ByteScanner.ScanAsync(stream, StreamKeyword, ScanMode.Exact, long.MaxValue, (_, end) =>
        {
            streams.Add(end);
            return true;
        }, cancellationToken);

        var budget = policy.MaxUncompressedBytes;
        foreach (var keywordEnd in streams)
        {
            if (await FlateDataStartAsync(stream, keywordEnd, cancellationToken) is not { } start)
            {
                continue;
            }

            stream.Position = start;
            try
            {
                await using var inflated = new ZLibStream(stream, CompressionMode.Decompress, leaveOpen: true);
                var hit = -1;
                var read = await ByteScanner.ScanAsync(inflated, Patterns, ScanMode.PdfNames, budget + 1, (index, _) =>
                {
                    hit = index;
                    return false;
                }, cancellationToken);
                if (hit >= 0)
                {
                    return Active(hit);
                }

                budget -= read;
                if (budget < 0)
                {
                    return new(UploadErrorCode.ArchiveTooLarge, $"The PDF streams unpack to more than {policy.MaxUncompressedBytes} bytes.");
                }
            }
            catch (InvalidDataException)
            {
                // Not zlib data after all, or truncated: nothing more to inspect in this stream.
            }
        }

        return null;
    }

    // "stream" (not "endstream"), then CRLF or LF, then a zlib header.
    private static async Task<long?> FlateDataStartAsync(Stream stream, long keywordEnd, CancellationToken cancellationToken)
    {
        const int Before = 9; // "endstream".Length
        var from = Math.Max(0, keywordEnd - Before);
        var window = new byte[Before + 4];
        stream.Position = from;
        var read = await stream.ReadAtLeastAsync(window, window.Length, throwOnEndOfStream: false, cancellationToken);
        var keyword = (int)(keywordEnd - from);
        if (keyword >= Before && window.AsSpan(0, 3).SequenceEqual("end"u8))
        {
            return null;
        }

        var data = keyword;
        if (data < read && window[data] == '\r')
        {
            data++;
        }

        if (data < read && window[data] == '\n')
        {
            data++;
        }

        if (data == keyword || data + 2 > read)
        {
            return null;
        }

        var cmf = window[data];
        var flg = window[data + 1];
        return (cmf & 0x0F) == 8 && ((cmf << 8) | flg) % 31 == 0 ? from + data : null;
    }

    private static UploadError Active(int pattern) =>
        new(UploadErrorCode.ActiveContent, $"The PDF contains {Features[pattern].What}.");
}
