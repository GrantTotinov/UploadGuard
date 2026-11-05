using System.Text;

namespace UploadGuard.Tests;

public sealed class ContentTests
{
    private static readonly UploadPipeline All = TestPipeline.AllowAll();

    // Archives

    [Fact]
    public async Task Zip_with_too_many_entries_is_rejected()
    {
        var pipeline = TestPipeline.Create(p => p.Allow(FileTypes.Zip).LimitArchives(maxEntries: 5));
        var zip = Samples.Zip([.. Enumerable.Range(0, 6).Select(i => ($"{i}.txt", Samples.Utf8("x")))]);

        Assert.Equal(UploadErrorCode.ArchiveTooLarge, await pipeline.ErrorAsync(zip, "many.zip"));
    }

    [Fact]
    public async Task Zip_that_unpacks_past_the_size_limit_is_rejected()
    {
        var pipeline = TestPipeline.Create(p => p.Allow(FileTypes.Zip).LimitArchives(maxUncompressedSize: 1_000_000));
        var zip = Samples.Zip(("random.bin", RandomBytes(600_000)), ("random2.bin", RandomBytes(600_000)));

        Assert.Equal(UploadErrorCode.ArchiveTooLarge, await pipeline.ErrorAsync(zip, "big.zip"));
    }

    [Fact]
    public async Task Zip_bomb_is_rejected_by_compression_ratio()
    {
        var zip = Samples.Zip(("zeros.bin", new byte[20_000_000]));

        var result = await All.CheckAsync(zip, "bomb.zip");

        Assert.Equal(UploadErrorCode.ArchiveTooLarge, result.Error?.Code);
        Assert.Contains("100 times", result.Error!.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Office_documents_get_the_zip_bomb_checks_too()
    {
        var docx = Samples.Office(
            "word/document.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            extra: ("word/media/zeros.bin", new byte[20_000_000]));

        Assert.Equal(UploadErrorCode.ArchiveTooLarge, await All.ErrorAsync(docx, "bomb.docx"));
    }

    [Theory]
    [InlineData("../evil.txt")]
    [InlineData("a/../../evil.txt")]
    [InlineData("..\\evil.txt")]
    [InlineData("/etc/cron.d/evil")]
    [InlineData("C:/Windows/evil.dll")]
    public async Task Zip_slip_is_rejected(string entryName)
    {
        var zip = Samples.Zip(("ok.txt", Samples.Utf8("x")), (entryName, Samples.Utf8("x")));

        Assert.Equal(UploadErrorCode.UnsafeArchive, await All.ErrorAsync(zip, "slip.zip"));
    }

    [Fact]
    public async Task Encrypted_zip_is_rejected()
    {
        var zip = Samples.MarkEncrypted(Samples.All[FileTypes.Zip].Data);

        Assert.Equal(UploadErrorCode.UnsafeArchive, await All.ErrorAsync(zip, "secret.zip"));
    }

    [Fact]
    public async Task Damaged_zip_is_rejected()
    {
        var zip = Samples.Concat([0x50, 0x4B, 0x03, 0x04], Encoding.ASCII.GetBytes("this is not a zip at all, just junk"));

        Assert.Equal(UploadErrorCode.Corrupt, await All.ErrorAsync(zip, "broken.zip"));
    }

    [Theory]
    [InlineData("Basic/Standard/Module1.xml")]
    [InlineData("Scripts/python/evil.py")]
    public async Task OpenDocument_with_macros_is_rejected(string entry)
    {
        var odt = Samples.OpenDocument("application/vnd.oasis.opendocument.text", (entry, Samples.Utf8("x")));

        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(odt, "notes.odt"));
    }

    [Fact]
    public async Task Gzip_bomb_is_rejected()
    {
        Assert.Equal(UploadErrorCode.ArchiveTooLarge, await All.ErrorAsync(Samples.Gzip(new byte[20_000_000]), "bomb.gz"));
    }

    [Fact]
    public async Task Damaged_gzip_is_rejected()
    {
        var gzip = Samples.Concat([0x1F, 0x8B, 0x08, 0x00], new byte[12], Encoding.ASCII.GetBytes("garbage"));

        Assert.Equal(UploadErrorCode.Corrupt, await All.ErrorAsync(gzip, "broken.gz"));
    }

    // PDF

    [Theory]
    [InlineData("<</Type /Action /S /JavaScript /JS (app.alert(1))>>")]
    [InlineData("<</S /JavaScript /JS<6170702e616c657274283129>>>")]
    [InlineData("<</OpenAction <</S/JavaScript/JS(app.alert(1))>>>>")]
    [InlineData("<</AA <</O <</JS (this.exportDataObject())>>>>>>")]
    [InlineData("<</S /J#61vaScript>>")]
    [InlineData("<</S /Launch /F (cmd.exe)>>")]
    [InlineData("<</Type /EmbeddedFile /Subtype /application#2Fx-msdownload>>")]
    [InlineData("<</Names <</EmbeddedFiles 9 0 R>>>>")]
    [InlineData("<</AcroForm <</XFA 7 0 R>>>>")]
    [InlineData("<</Type /RichMedia>>")]
    public async Task Pdf_with_active_content_is_rejected(string dictionary)
    {
        var pdf = Samples.Pdf($"1 0 obj {dictionary} endobj");

        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(pdf, "invoice.pdf"));
    }

    [Fact]
    public async Task Pdf_javascript_hidden_in_a_compressed_object_stream_is_rejected()
    {
        var pdf = Samples.PdfWithCompressedObject("1 0 <</Type /Catalog /OpenAction <</S /JavaScript /JS (app.alert(1))>>>>");

        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(pdf, "invoice.pdf"));
    }

    [Theory]
    [InlineData("<</Filter /JBIG2Decode /JSONish 1>>")]
    [InlineData("<</Font <</F1 5 0 R>> /URI (https://example.com)>>")]
    public async Task Pdf_without_active_content_is_accepted(string dictionary)
    {
        var pdf = Samples.Pdf($"1 0 obj {dictionary} endobj");

        Assert.Null(await All.ErrorAsync(pdf, "invoice.pdf"));
    }

    [Fact]
    public async Task Clean_compressed_pdf_is_accepted()
    {
        var pdf = Samples.PdfWithCompressedObject("1 0 <</Type /Catalog /Pages 2 0 R>>");

        Assert.Null(await All.ErrorAsync(pdf, "invoice.pdf"));
    }

    [Fact]
    public async Task Pdf_streams_are_inflated_only_up_to_the_limit()
    {
        var pipeline = TestPipeline.Create(p => p.Allow(FileTypes.Pdf).LimitArchives(maxUncompressedSize: 1_000));
        var pdf = Samples.PdfWithCompressedObject(new string(' ', 5_000));

        Assert.Equal(UploadErrorCode.ArchiveTooLarge, await pipeline.ErrorAsync(pdf, "invoice.pdf"));
    }

    // SVG

    [Theory]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<SCRIPT>alert(1)</SCRIPT>")]
    [InlineData("<rect onload=\"alert(1)\"/>")]
    [InlineData("<rect ONMOUSEOVER=\"alert(1)\"/>")]
    [InlineData("<a href=\"javascript:alert(1)\"><text>x</text></a>")]
    [InlineData("<a xlink:href=\"java&#x09;script:alert(1)\"><text>x</text></a>")]
    [InlineData("<a href=\" JaVaScRiPt:alert(1)\"><text>x</text></a>")]
    [InlineData("<animate attributeName=\"href\" values=\"javascript:alert(1)\"/>")]
    [InlineData("<foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"/></foreignObject>")]
    [InlineData("<iframe src=\"https://evil.example\"/>")]
    [InlineData("<image href=\"data:image/svg+xml;base64,PHN2Zy8+\"/>")]
    [InlineData("<style>@import url(\"javascript:alert(1)\");</style>")]
    public async Task Svg_that_can_run_script_is_rejected(string body)
    {
        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(Samples.Utf8(Samples.Svg(body)), "logo.svg"));
    }

    [Fact]
    public async Task Svg_stylesheet_processing_instruction_is_rejected()
    {
        var svg = "<?xml version=\"1.0\"?><?xml-stylesheet type=\"text/xsl\" href=\"evil.xsl\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>";

        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(Samples.Utf8(svg), "logo.svg"));
    }

    [Fact]
    public async Task Svg_with_a_doctype_is_accepted_without_expanding_it()
    {
        var svg = "<?xml version=\"1.0\"?><!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">" +
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0 0h1v1z\" opacity=\"0.5\"/></svg>";

        Assert.Null(await All.ErrorAsync(Samples.Utf8(svg), "logo.svg"));
    }

    [Fact]
    public async Task Svg_entity_expansion_is_never_performed()
    {
        var svg = "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;\">]>" +
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><text>&lol2;</text></svg>";

        Assert.Equal(UploadErrorCode.Corrupt, await All.ErrorAsync(Samples.Utf8(svg), "lol.svg"));
    }

    [Fact]
    public async Task Malformed_svg_is_rejected()
    {
        Assert.Equal(UploadErrorCode.Corrupt, await All.ErrorAsync(Samples.Utf8("<svg xmlns=\"http://www.w3.org/2000/svg\"><rect>"), "logo.svg"));
    }

    // Images and legacy Office

    [Theory]
    [InlineData("<?php system($_GET['c']); ?>")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<HTML><BODY>")]
    [InlineData("<iframe src=//evil>")]
    public async Task Image_carrying_script_or_html_is_rejected(string payload)
    {
        var jpeg = Samples.Concat(Samples.Jpeg(), Samples.Utf8(payload));
        var png = Samples.Concat(Samples.Png(), Samples.Utf8(payload));

        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(jpeg, "photo.jpg"));
        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(png, "photo.png"));
    }

    [Fact]
    public async Task Gif_html_polyglot_is_rejected()
    {
        var gif = Samples.Concat(Samples.Utf8("GIF89a"), [0x01, 0x00, 0x01, 0x00], Samples.Utf8("<script src=//evil></script>"));

        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(gif, "funny.gif"));
    }

    [Fact]
    public async Task Marker_split_across_scan_chunks_is_found()
    {
        // ByteScanner reads 64 KB chunks; put the marker across the first boundary.
        var jpeg = Samples.Concat(Samples.Jpeg(), new byte[(64 * 1024) - Samples.Jpeg().Length - 3], Samples.Utf8("<?php"));

        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(jpeg, "photo.jpg"));
    }

    [Theory]
    [InlineData("old.doc")]
    [InlineData("old.xls")]
    [InlineData("old.ppt")]
    public async Task Legacy_office_with_a_vba_project_is_rejected(string name)
    {
        Assert.Equal(UploadErrorCode.ActiveContent, await All.ErrorAsync(Samples.Ole(macros: true), name));
    }

    private static byte[] RandomBytes(int length)
    {
        var data = new byte[length];
        new Random(42).NextBytes(data);
        return data;
    }
}
