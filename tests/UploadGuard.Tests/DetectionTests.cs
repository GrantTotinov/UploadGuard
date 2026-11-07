namespace UploadGuard.Tests;

public sealed class DetectionTests
{
    public static TheoryData<string> TypeNames => [.. FileTypes.All.Select(t => t.Name)];

    [Fact]
    public void Every_type_has_a_sample()
    {
        Assert.Empty(FileTypes.All.Except(Samples.All.Keys));
    }

    [Theory]
    [MemberData(nameof(TypeNames))]
    public async Task Sample_is_detected_as_its_type(string typeName)
    {
        var type = FileTypes.All.Single(t => t.Name == typeName);
        var (data, name) = Samples.All[type];

        var result = await TestPipeline.AllowAll().CheckAsync(data, name, type.MimeType);

        Assert.Null(result.Error);
        Assert.Same(type, result.FileType);
    }

    [Theory]
    [InlineData("photo.png")] // JPEG content
    [InlineData("photo.gif")]
    [InlineData("photo.exe")]
    [InlineData("photo")]
    public async Task Jpeg_with_another_extension_is_a_mismatch(string name)
    {
        var result = await TestPipeline.AllowAll().CheckAsync(Samples.Jpeg(), name);

        Assert.Equal(UploadErrorCode.ExtensionMismatch, result.Error?.Code);
        Assert.Same(FileTypes.Jpeg, result.FileType);
    }

    [Theory]
    [InlineData("<?php system($_GET['c']); ?>", "shell.jpg")]
    [InlineData("<?php system($_GET['c']); ?>", "shell.php")]
    [InlineData("<html><script>alert(1)</script></html>", "cute.png")]
    [InlineData("<!DOCTYPE html><html><body>phish</body></html>", "notes.txt")]
    [InlineData("<script>alert(1)</script>", "data.csv")]
    [InlineData("<svg xmlns=\"http://www.w3.org/2000/svg\"/>", "logo.png")]
    [InlineData("#!/bin/sh\nrm -rf /\n", "notes.txt")]
    public async Task Script_disguised_by_extension_is_a_mismatch(string content, string name)
    {
        Assert.Equal(UploadErrorCode.ExtensionMismatch, await TestPipeline.AllowAll().ErrorAsync(Samples.Utf8(content), name));
    }

    [Theory]
    [InlineData("export.csv")]
    [InlineData("export.txt")]
    public async Task Extension_picks_between_types_with_the_same_content(string name)
    {
        var result = await TestPipeline.AllowAll().CheckAsync(Samples.Utf8("a,b\n1,2\n"), name);

        Assert.Equal(Path.GetExtension(name), result.FileType?.Extensions[0]);
    }

    [Fact]
    public async Task Macro_enabled_document_renamed_to_docx_is_a_mismatch()
    {
        var result = await TestPipeline.AllowAll().CheckAsync(Samples.All[FileTypes.Docm].Data, "invoice.docx");

        Assert.Equal(UploadErrorCode.ExtensionMismatch, result.Error?.Code);
        Assert.Same(FileTypes.Docm, result.FileType);
    }

    [Fact]
    public async Task VBA_project_makes_a_document_macro_enabled_even_with_a_docx_content_type()
    {
        var data = Samples.Office(
            "word/document.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            extra: ("word/vbaProject.bin", [1, 2, 3]));

        var result = await TestPipeline.AllowAll().CheckAsync(data, "invoice.docx");

        Assert.Same(FileTypes.Docm, result.FileType);
        Assert.Equal(UploadErrorCode.ExtensionMismatch, result.Error?.Code);
    }

    [Theory]
    [InlineData(new byte[] { 0x00, 0x01, 0x02, 0x03, 0xFE, 0x10, 0x00, 0x99 })]
    [InlineData(new byte[] { 0xC3, 0x28 })] // invalid UTF-8
    [InlineData(new byte[] { 0x48, 0x69, 0x00, 0x21 })] // text with a NUL byte
    public async Task Unknown_content_is_rejected(byte[] data)
    {
        Assert.Equal(UploadErrorCode.UnknownType, await TestPipeline.AllowAll().ErrorAsync(data, "file.txt"));
    }

    [Fact]
    public async Task Utf16_text_with_bom_is_text()
    {
        var data = Samples.Concat([0xFF, 0xFE], System.Text.Encoding.Unicode.GetBytes("Hello\r\n"));

        var result = await TestPipeline.AllowAll().CheckAsync(data, "notes.txt");

        Assert.Same(FileTypes.Text, result.FileType);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Svg_with_a_leading_comment_is_svg_not_html()
    {
        var data = Samples.Utf8("<!-- Generator: Adobe Illustrator --> <svg xmlns=\"http://www.w3.org/2000/svg\"/>");

        var result = await TestPipeline.AllowAll().CheckAsync(data, "logo.svg");

        Assert.Same(FileTypes.Svg, result.FileType);
    }
}
