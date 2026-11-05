using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using SkiaSharp;

namespace UploadGuard.Tests;

/// <summary>
/// Generates every test file in memory: the suite ships no binary samples and no real malware. The smallest
/// structure that makes each format recognizable, or a real image from SkiaSharp where it must decode.
/// </summary>
internal static class Samples
{
    /// <summary>A valid sample and file name for every type UploadGuard detects.</summary>
    public static IReadOnlyDictionary<FileType, (byte[] Data, string Name)> All { get; } = new Dictionary<FileType, (byte[], string)>
    {
        [FileTypes.Jpeg] = (Jpeg(), "photo.jpg"),
        [FileTypes.Png] = (Png(), "image.png"),
        [FileTypes.Gif] = (Gif(), "anim.gif"),
        [FileTypes.Webp] = (Webp(), "image.webp"),
        [FileTypes.Bmp] = (Bmp(), "image.bmp"),
        [FileTypes.Tiff] = (Pad("II*\0\b\0\0\0"u8, 64), "scan.tiff"),
        [FileTypes.Ico] = (Ico(), "favicon.ico"),
        [FileTypes.Heic] = (Ftyp("heic", "mif1", "heic"), "IMG_0001.heic"),
        [FileTypes.Avif] = (Ftyp("avif", "avif", "mif1", "miaf"), "image.avif"),
        [FileTypes.Svg] = (Utf8(Svg("<rect width=\"1\" height=\"1\" fill=\"red\"/>")), "logo.svg"),
        [FileTypes.Pdf] = (Pdf("1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj"), "invoice.pdf"),
        [FileTypes.Docx] = (Office("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"), "letter.docx"),
        [FileTypes.Docm] = (Office("word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml", macros: true), "letter.docm"),
        [FileTypes.Xlsx] = (Office("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"), "budget.xlsx"),
        [FileTypes.Xlsm] = (Office("xl/workbook.xml", "application/vnd.ms-excel.sheet.macroEnabled.main+xml", macros: true), "budget.xlsm"),
        [FileTypes.Pptx] = (Office("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"), "deck.pptx"),
        [FileTypes.Pptm] = (Office("ppt/presentation.xml", "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml", macros: true), "deck.pptm"),
        [FileTypes.Doc] = (Ole(), "old.doc"),
        [FileTypes.Xls] = (Ole(), "old.xls"),
        [FileTypes.Ppt] = (Ole(), "old.ppt"),
        [FileTypes.Odt] = (OpenDocument("application/vnd.oasis.opendocument.text"), "notes.odt"),
        [FileTypes.Ods] = (OpenDocument("application/vnd.oasis.opendocument.spreadsheet"), "sheet.ods"),
        [FileTypes.Odp] = (OpenDocument("application/vnd.oasis.opendocument.presentation"), "slides.odp"),
        [FileTypes.Rtf] = (Utf8("{\\rtf1\\ansi Hello}"), "memo.rtf"),
        [FileTypes.Text] = (Utf8("Hello, world.\r\nSecond line.\n"), "readme.txt"),
        [FileTypes.Csv] = (Utf8("name,amount\nAda,10\n"), "export.csv"),
        [FileTypes.Xml] = (Utf8("<?xml version=\"1.0\"?><order id=\"1\"/>"), "order.xml"),
        [FileTypes.Html] = (Utf8("<!DOCTYPE html><html><body>Hi</body></html>"), "page.html"),
        [FileTypes.Zip] = (Zip(("a.txt", Utf8("hello"))), "archive.zip"),
        [FileTypes.Gzip] = (Gzip(Utf8("hello hello hello")), "log.gz"),
        [FileTypes.SevenZip] = (Pad([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04], 64), "archive.7z"),
        [FileTypes.Rar] = (Pad("Rar!\u001A\a\u0001\0"u8, 64), "archive.rar"),
        [FileTypes.Tar] = (Tar(), "archive.tar"),
        [FileTypes.Mp3] = (Mp3(), "song.mp3"),
        [FileTypes.Wav] = (Riff("WAVE"), "sound.wav"),
        [FileTypes.Ogg] = (Pad("OggS\0\u0002"u8, 64), "voice.ogg"),
        [FileTypes.Flac] = (Pad("fLaC"u8, 64), "track.flac"),
        [FileTypes.M4a] = (Ftyp("M4A ", "M4A ", "mp42", "isom"), "voice.m4a"),
        [FileTypes.Mp4] = (Ftyp("isom", "isom", "iso2", "avc1", "mp41"), "clip.mp4"),
        [FileTypes.Mov] = (Ftyp("qt  ", "qt  "), "clip.mov"),
        [FileTypes.Webm] = (Ebml("webm"), "clip.webm"),
        [FileTypes.Mkv] = (Ebml("matroska"), "movie.mkv"),
        [FileTypes.Avi] = (Riff("AVI "), "movie.avi"),
        [FileTypes.Exe] = (Pad("MZ\u0090\0\u0003\0"u8, 128), "setup.exe"),
        [FileTypes.Elf] = (Pad([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01], 64), "tool.elf"),
        [FileTypes.MachO] = (Pad([0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01], 64), "lib.dylib"),
        [FileTypes.ShellScript] = (Utf8("#!/bin/sh\necho hi\n"), "run.sh"),
    };

    public static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);

    public static byte[] Concat(params byte[][] parts) => [.. parts.SelectMany(p => p)];

    public static string Svg(string body) =>
        $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" width=\"1\" height=\"1\">{body}</svg>";

    public static byte[] Jpeg(int width = 8, int height = 8) => Encode(width, height, SKEncodedImageFormat.Jpeg);

    public static byte[] Png(int width = 8, int height = 8) => Encode(width, height, SKEncodedImageFormat.Png);

    public static byte[] Webp(bool lossless = false)
    {
        using var bitmap = Bitmap(8, 8);
        using var pixmap = bitmap.PeekPixels();
        var options = new SKWebpEncoderOptions(lossless ? SKWebpEncoderCompression.Lossless : SKWebpEncoderCompression.Lossy, 90);
        using var data = pixmap.Encode(options)!;
        return data.ToArray();
    }

    // A 1x1 GIF89a.
    public static byte[] Gif() =>
    [
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
    ];

    // A 2x2 24-bit BMP.
    public static byte[] Bmp()
    {
        const int RowSize = 8; // 2 pixels * 3 bytes, padded to 4
        var data = new byte[54 + (RowSize * 2)];
        "BM"u8.CopyTo(data);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(2), data.Length);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(10), 54);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(14), 40);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(18), 2);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(22), 2);
        BinaryPrimitives.WriteInt16LittleEndian(data.AsSpan(26), 1);
        BinaryPrimitives.WriteInt16LittleEndian(data.AsSpan(28), 24);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(34), RowSize * 2);
        data.AsSpan(54).Fill(0x80);
        return data;
    }

    public static byte[] Pdf(string body) =>
        Utf8($"%PDF-1.7\n%âãÏÓ\n{body}\n2 0 obj <</Type /Pages /Kids [] /Count 0>> endobj\ntrailer <</Root 1 0 R>>\n%%EOF\n");

    /// <summary>A PDF whose only dictionary sits inside a FlateDecode object stream.</summary>
    public static byte[] PdfWithCompressedObject(string objectBody)
    {
        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(Utf8(objectBody));
        }

        return Concat(
            Utf8($"%PDF-1.7\n3 0 obj <</Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length {compressed.Length}>>\nstream\r\n"),
            compressed.ToArray(),
            Utf8("\r\nendstream\nendobj\ntrailer <</Root 1 0 R>>\n%%EOF\n"));
    }

    public static byte[] Office(string mainPart, string mainContentType, bool macros = false, params (string Name, byte[] Data)[] extra)
    {
        var contentTypes =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
            "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
            (macros ? "<Default Extension=\"bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/>" : "") +
            $"<Override PartName=\"/{mainPart}\" ContentType=\"{mainContentType}\"/></Types>";
        var entries = new List<(string, byte[])> { ("[Content_Types].xml", Utf8(contentTypes)), (mainPart, Utf8("<doc/>")) };
        if (macros)
        {
            entries.Add((Path.GetDirectoryName(mainPart)!.Replace('\\', '/') + "/vbaProject.bin", [0xCC, 0x61, 0xFF]));
        }

        entries.AddRange(extra);
        return Zip([.. entries]);
    }

    public static byte[] OpenDocument(string mimeType, params (string Name, byte[] Data)[] extra) =>
        Zip([("mimetype", Utf8(mimeType)), ("content.xml", Utf8("<office:document-content/>")), .. extra]);

    // The Compound File signature followed by a sector of zeros, optionally with a VBA project directory name.
    public static byte[] Ole(bool macros = false)
    {
        var data = new byte[1024];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(data, 0);
        if (macros)
        {
            Encoding.Unicode.GetBytes("_VBA_PROJECT_CUR").CopyTo(data, 600);
        }

        return data;
    }

    public static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in entries)
            {
                using var stream = zip.CreateEntry(name, name == "mimetype" ? CompressionLevel.NoCompression : CompressionLevel.Optimal).Open();
                stream.Write(data);
            }
        }

        return output.ToArray();
    }

    /// <summary>Sets the "encrypted" flag on every entry, in both local and central headers.</summary>
    public static byte[] MarkEncrypted(byte[] zip)
    {
        var data = (byte[])zip.Clone();
        for (var i = 0; i + 4 <= data.Length; i++)
        {
            if (data.AsSpan(i).StartsWith(new byte[] { 0x50, 0x4B, 0x03, 0x04 }))
            {
                data[i + 6] |= 1;
            }
            else if (data.AsSpan(i).StartsWith(new byte[] { 0x50, 0x4B, 0x01, 0x02 }))
            {
                data[i + 8] |= 1;
            }
        }

        return data;
    }

    public static byte[] Gzip(byte[] content)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(content);
        }

        return output.ToArray();
    }

    // The EICAR test string (harmless by design, detected by every antivirus). Split so this source file is not flagged.
    public static byte[] Eicar() => Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    private static byte[] Ftyp(string major, params string[] compatible)
    {
        var size = 16 + (4 * compatible.Length);
        var data = new byte[size + 16];
        BinaryPrimitives.WriteInt32BigEndian(data, size);
        Encoding.ASCII.GetBytes("ftyp" + major).CopyTo(data, 4);
        for (var i = 0; i < compatible.Length; i++)
        {
            Encoding.ASCII.GetBytes(compatible[i]).CopyTo(data, 16 + (4 * i));
        }

        return data;
    }

    private static byte[] Riff(string form)
    {
        var data = Pad("RIFF"u8, 64);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(4), data.Length - 8);
        Encoding.ASCII.GetBytes(form).CopyTo(data, 8);
        return data;
    }

    private static byte[] Ebml(string docType) =>
        Concat([0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86, 0x81, 0x01, 0x42, 0x82, (byte)(0x80 | docType.Length)], Encoding.ASCII.GetBytes(docType), new byte[32]);

    private static byte[] Mp3() => Concat("ID3\u0004\0\0\0\0\0\0"u8.ToArray(), [0xFF, 0xFB, 0x90, 0x44], new byte[413]);

    private static byte[] Tar()
    {
        var data = new byte[1024];
        "hello.txt"u8.CopyTo(data);
        "ustar\u000000"u8.CopyTo(data.AsSpan(257));
        return data;
    }

    private static byte[] Ico()
    {
        var data = new byte[64];
        new byte[] { 0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0 }.CopyTo(data, 0);
        return data;
    }

    private static byte[] Pad(ReadOnlySpan<byte> start, int length)
    {
        var data = new byte[length];
        start.CopyTo(data);
        return data;
    }

    private static SKBitmap Bitmap(int width, int height)
    {
        var bitmap = new SKBitmap(width, height);
        using var canvas = new SKCanvas(bitmap);
        canvas.Clear(SKColors.CornflowerBlue);
        return bitmap;
    }

    private static byte[] Encode(int width, int height, SKEncodedImageFormat format)
    {
        using var bitmap = Bitmap(width, height);
        using var data = bitmap.Encode(format, 90);
        return data.ToArray();
    }
}
