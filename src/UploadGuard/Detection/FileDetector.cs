using System.Buffers.Binary;
using System.Text;

namespace UploadGuard.Detection;

/// <summary>Finds the file type from the content alone. The extension and Content-Type are never consulted.</summary>
internal static class FileDetector
{
    private const int HeaderSize = 4096;
    private const int TextPrefixLength = 4096;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly string[] HtmlPatterns =
        ["<head", "<script", "<iframe", "<h1", "<div", "<font", "<table", "<a", "<style", "<title", "<b", "<body", "<br", "<p", "<!--"];
    private static readonly byte[][] HeicBrands =
        ["heic"u8.ToArray(), "heix"u8.ToArray(), "hevc"u8.ToArray(), "hevx"u8.ToArray(), "heim"u8.ToArray(), "heis"u8.ToArray(), "mif1"u8.ToArray(), "msf1"u8.ToArray()];

    private static ReadOnlySpan<byte> JpegMagic => [0xFF, 0xD8, 0xFF];
    private static ReadOnlySpan<byte> PngMagic => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static ReadOnlySpan<byte> OleMagic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    private static ReadOnlySpan<byte> GzipMagic => [0x1F, 0x8B, 0x08];
    private static ReadOnlySpan<byte> SevenZipMagic => [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    private static ReadOnlySpan<byte> RarMagic => [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07];
    private static ReadOnlySpan<byte> EbmlMagic => [0x1A, 0x45, 0xDF, 0xA3];
    private static ReadOnlySpan<byte> ElfMagic => [0x7F, 0x45, 0x4C, 0x46];
    private static ReadOnlySpan<byte> IcoMagic => [0x00, 0x00, 0x01, 0x00];
    private static ReadOnlySpan<byte> ZipMagic => [0x50, 0x4B, 0x03, 0x04];
    private static ReadOnlySpan<byte> EmptyZipMagic => [0x50, 0x4B, 0x05, 0x06];

    /// <summary>Returns the candidate types, best match first, or an empty array when the content is unknown.</summary>
    /// <remarks>Several candidates means the content cannot tell them apart (CSV vs text, DOC vs XLS); the extension picks one.</remarks>
    public static async Task<FileType[]> DetectAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[HeaderSize];
        stream.Position = 0;
        var read = await stream.ReadAtLeastAsync(header, HeaderSize, throwOnEndOfStream: false, cancellationToken);
        if (IsZip(header.AsSpan(0, read)))
        {
            return await ArchiveInspector.DetectAsync(stream, cancellationToken);
        }

        var match = MatchSignature(header.AsSpan(0, read));
        return match ?? await DetectTextAsync(stream, cancellationToken);
    }

    private static bool IsZip(ReadOnlySpan<byte> h) => h.StartsWith(ZipMagic) || h.StartsWith(EmptyZipMagic);

    internal static FileType[]? MatchSignature(ReadOnlySpan<byte> h)
    {
        if (h.StartsWith(JpegMagic))
        {
            return [FileTypes.Jpeg];
        }

        if (h.StartsWith(PngMagic))
        {
            return [FileTypes.Png];
        }

        if (h.StartsWith("GIF87a"u8) || h.StartsWith("GIF89a"u8))
        {
            return [FileTypes.Gif];
        }

        if (h.Length >= 12 && h.StartsWith("RIFF"u8))
        {
            var form = h.Slice(8, 4);
            return form.SequenceEqual("WEBP"u8) ? [FileTypes.Webp]
                : form.SequenceEqual("WAVE"u8) ? [FileTypes.Wav]
                : form.SequenceEqual("AVI "u8) ? [FileTypes.Avi]
                : null;
        }

        if (h.StartsWith("%PDF-"u8))
        {
            return [FileTypes.Pdf];
        }

        if (h.StartsWith(OleMagic))
        {
            return [FileTypes.Doc, FileTypes.Xls, FileTypes.Ppt];
        }

        if (h.StartsWith("{\\rtf"u8))
        {
            return [FileTypes.Rtf];
        }

        if (h.StartsWith("II*\0"u8) || h.StartsWith("MM\0*"u8))
        {
            return [FileTypes.Tiff];
        }

        if (IsBmp(h))
        {
            return [FileTypes.Bmp];
        }

        if (IsIco(h))
        {
            return [FileTypes.Ico];
        }

        if (h.Length >= 16 && h.Slice(4, 4).SequenceEqual("ftyp"u8))
        {
            return [IsoMedia(h)];
        }

        if (h.StartsWith(GzipMagic))
        {
            return [FileTypes.Gzip];
        }

        if (h.StartsWith(SevenZipMagic))
        {
            return [FileTypes.SevenZip];
        }

        if (h.StartsWith(RarMagic))
        {
            return [FileTypes.Rar];
        }

        if (h.Length >= 262 && h.Slice(257, 5).SequenceEqual("ustar"u8))
        {
            return [FileTypes.Tar];
        }

        if (h.StartsWith("ID3"u8) || IsMpegAudioFrame(h))
        {
            return [FileTypes.Mp3];
        }

        if (h.StartsWith("OggS"u8))
        {
            return [FileTypes.Ogg];
        }

        if (h.StartsWith("fLaC"u8))
        {
            return [FileTypes.Flac];
        }

        if (h.StartsWith(EbmlMagic))
        {
            return h[..Math.Min(h.Length, 64)].IndexOf("webm"u8) >= 0 ? [FileTypes.Webm] : [FileTypes.Mkv];
        }

        if (h.StartsWith("MZ"u8))
        {
            return [FileTypes.Exe];
        }

        if (h.StartsWith(ElfMagic))
        {
            return [FileTypes.Elf];
        }

        if (h.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(h) is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE)
        {
            return [FileTypes.MachO];
        }

        return null;
    }

    // "BM", zero reserved bytes, and a known DIB header size: "BM" alone matches too much text.
    private static bool IsBmp(ReadOnlySpan<byte> h) =>
        h.Length >= 18
        && h.StartsWith("BM"u8)
        && BinaryPrimitives.ReadUInt32LittleEndian(h[6..]) == 0
        && BinaryPrimitives.ReadUInt32LittleEndian(h[14..]) is 12 or 40 or 52 or 56 or 64 or 108 or 124;

    // ICONDIR with at least one image, then an ICONDIRENTRY whose reserved byte is 0 and planes is 0 or 1.
    private static bool IsIco(ReadOnlySpan<byte> h) =>
        h.Length >= 22
        && h.StartsWith(IcoMagic)
        && BinaryPrimitives.ReadUInt16LittleEndian(h[4..]) > 0
        && h[9] == 0
        && BinaryPrimitives.ReadUInt16LittleEndian(h[10..]) <= 1;

    // MPEG-1/2/2.5 Layer III frame header without ID3 tag: sync bits, valid version, bitrate and sample rate.
    private static bool IsMpegAudioFrame(ReadOnlySpan<byte> h) =>
        h.Length >= 3
        && h[0] == 0xFF
        && (h[1] & 0xE0) == 0xE0
        && ((h[1] >> 3) & 3) != 1
        && ((h[1] >> 1) & 3) == 1
        && (h[2] >> 4) is not 0 and not 15
        && ((h[2] >> 2) & 3) != 3;

    // ISO base media file: the ftyp box lists a major brand and compatible brands.
    private static FileType IsoMedia(ReadOnlySpan<byte> h)
    {
        var size = (int)Math.Clamp(BinaryPrimitives.ReadUInt32BigEndian(h), 16u, (uint)h.Length);
        if (HasBrand(h, size, "avif"u8) || HasBrand(h, size, "avis"u8))
        {
            return FileTypes.Avif;
        }

        foreach (var brand in HeicBrands)
        {
            if (HasBrand(h, size, brand))
            {
                return FileTypes.Heic;
            }
        }

        var major = h.Slice(8, 4);
        if (major.SequenceEqual("qt  "u8))
        {
            return FileTypes.Mov;
        }

        return major.SequenceEqual("M4A "u8) || major.SequenceEqual("M4B "u8) ? FileTypes.M4a : FileTypes.Mp4;
    }

    private static bool HasBrand(ReadOnlySpan<byte> h, int boxSize, ReadOnlySpan<byte> brand)
    {
        if (h.Slice(8, 4).SequenceEqual(brand))
        {
            return true;
        }

        for (var i = 16; i + 4 <= boxSize; i += 4)
        {
            if (h.Slice(i, 4).SequenceEqual(brand))
            {
                return true;
            }
        }

        return false;
    }

    // Text is the whole file decoding strictly, without control characters other than tab, CR, LF and form feed.
    private static async Task<FileType[]> DetectTextAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bom = new byte[3];
        stream.Position = 0;
        var bomRead = await stream.ReadAtLeastAsync(bom, bom.Length, throwOnEndOfStream: false, cancellationToken);
        (Encoding encoding, var skip) = bom switch
        {
            [0xEF, 0xBB, 0xBF] when bomRead == 3 => ((Encoding)StrictUtf8, 3),
            [0xFF, 0xFE, _] when bomRead >= 2 => (new UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true), 2),
            [0xFE, 0xFF, _] when bomRead >= 2 => (new UnicodeEncoding(bigEndian: true, byteOrderMark: false, throwOnInvalidBytes: true), 2),
            _ => (StrictUtf8, 0),
        };

        stream.Position = skip;
        var decoder = encoding.GetDecoder();
        var bytes = new byte[16 * 1024];
        var chars = new char[encoding.GetMaxCharCount(bytes.Length)];
        var prefix = new StringBuilder();
        try
        {
            int read;
            while ((read = await stream.ReadAsync(bytes, cancellationToken)) > 0)
            {
                var count = decoder.GetChars(bytes, 0, read, chars, 0, flush: false);
                if (!IsText(chars.AsSpan(0, count)))
                {
                    return [];
                }

                prefix.Append(chars, 0, Math.Min(count, TextPrefixLength - prefix.Length));
            }

            decoder.GetChars(bytes, 0, 0, chars, 0, flush: true);
        }
        catch (DecoderFallbackException)
        {
            return [];
        }

        return ClassifyText(prefix.ToString());
    }

    private static bool IsText(ReadOnlySpan<char> chars)
    {
        foreach (var c in chars)
        {
            if ((c < ' ' && c is not '\t' and not '\n' and not '\r' and not '\f') || c == '\u007F')
            {
                return false;
            }
        }

        return true;
    }

    // HTML is detected like browsers sniff it (WHATWG MIME Sniffing), so a page cannot pass as .txt or .csv.
    internal static FileType[] ClassifyText(string prefix)
    {
        var text = prefix.AsSpan().TrimStart();
        if (text.StartsWith("#!", StringComparison.Ordinal))
        {
            return [FileTypes.ShellScript];
        }

        if (text.IsEmpty || text[0] != '<')
        {
            return [FileTypes.Text, FileTypes.Csv];
        }

        if (StartsWithTag(text, "<!doctype html") || StartsWithTag(text, "<html"))
        {
            return [FileTypes.Html];
        }

        if (prefix.Contains("<svg", StringComparison.OrdinalIgnoreCase))
        {
            return [FileTypes.Svg];
        }

        foreach (var pattern in HtmlPatterns)
        {
            if (StartsWithTag(text, pattern))
            {
                return [FileTypes.Html];
            }
        }

        return [FileTypes.Xml, FileTypes.Text];
    }

    private static bool StartsWithTag(ReadOnlySpan<char> text, string tag) =>
        text.StartsWith(tag, StringComparison.OrdinalIgnoreCase)
        && text.Length > tag.Length
        && (text[tag.Length] is '>' || char.IsWhiteSpace(text[tag.Length]));
}
