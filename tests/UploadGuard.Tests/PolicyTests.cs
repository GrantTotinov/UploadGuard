namespace UploadGuard.Tests;

public sealed class PolicyTests
{
    private static readonly UploadPipeline Images = TestPipeline.Create(p => p.AllowImages().MaxSize(10_000));

    [Fact]
    public async Task Allowed_image_is_valid()
    {
        var result = await Images.CheckAsync(Samples.Jpeg(), "photo.jpg", "image/jpeg");

        Assert.True(result.IsValid);
        Assert.Equal("photo.jpg", result.FileName);
    }

    [Fact]
    public async Task Empty_file_is_rejected()
    {
        Assert.Equal(UploadErrorCode.Empty, await Images.ErrorAsync([], "photo.jpg"));
    }

    [Fact]
    public async Task File_over_the_limit_is_rejected_before_detection()
    {
        Assert.Equal(UploadErrorCode.TooLarge, await Images.ErrorAsync(new byte[10_001], "photo.jpg"));
    }

    [Fact]
    public async Task Type_outside_the_allow_list_is_rejected()
    {
        var (data, name) = Samples.All[FileTypes.Pdf];

        var result = await Images.CheckAsync(data, name);

        Assert.Equal(UploadErrorCode.TypeNotAllowed, result.Error?.Code);
        Assert.Same(FileTypes.Pdf, result.FileType);
    }

    [Fact]
    public async Task Svg_is_not_part_of_AllowImages()
    {
        var (data, name) = Samples.All[FileTypes.Svg];

        Assert.Equal(UploadErrorCode.TypeNotAllowed, await Images.ErrorAsync(data, name));
    }

    [Theory]
    [InlineData("image/jpeg")]
    [InlineData("IMAGE/JPEG")]
    [InlineData("image/pjpeg")]
    [InlineData("application/octet-stream")]
    [InlineData("image/jpeg; charset=binary")]
    [InlineData("")]
    [InlineData(null)]
    public async Task Matching_or_generic_content_type_is_accepted(string? contentType)
    {
        Assert.Null(await Images.ErrorAsync(Samples.Jpeg(), "photo.jpg", contentType));
    }

    [Theory]
    [InlineData("image/png")]
    [InlineData("text/html")]
    [InlineData("application/x-php")]
    public async Task Content_type_naming_another_type_is_rejected(string contentType)
    {
        Assert.Equal(UploadErrorCode.ContentTypeMismatch, await Images.ErrorAsync(Samples.Jpeg(), "photo.jpg", contentType));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("../../etc/passwd.jpg")]
    [InlineData("..\\..\\web.config.jpg")]
    [InlineData("C:\\Users\\me\\photo.jpg")]
    [InlineData("dir/photo.jpg")]
    [InlineData("photo\0.jpg")]
    [InlineData("photo\n.jpg")]
    [InlineData("invoice\u202Egpj.exe.jpg")]
    [InlineData("photo\u200B.jpg")]
    [InlineData(".htaccess.jpg")]
    [InlineData("photo.jpg.")]
    [InlineData("photo.jpg ")]
    [InlineData(" photo.jpg")]
    [InlineData("photo.jpg::$DATA")]
    [InlineData("CON.jpg")]
    [InlineData("nul .jpg")]
    [InlineData("shell.php.jpg")]
    [InlineData("shell.PHP5.jpg")]
    [InlineData("x.aspx.jpg")]
    [InlineData("report.html.jpg")]
    public async Task Hostile_file_name_is_rejected(string name)
    {
        Assert.Equal(UploadErrorCode.InvalidFileName, await Images.ErrorAsync(Samples.Jpeg(), name));
    }

    [Fact]
    public async Task Overlong_file_name_is_rejected()
    {
        Assert.Equal(UploadErrorCode.InvalidFileName, await Images.ErrorAsync(Samples.Jpeg(), new string('a', 252) + ".jpg"));
    }

    [Theory]
    [InlineData("my photo (1).jpg")]
    [InlineData("holiday.2026.v2.final.JPG")]
    [InlineData("снимка.jpeg")]
    [InlineData("写真.jpg")]
    public async Task Ordinary_file_names_are_accepted(string name)
    {
        Assert.Null(await Images.ErrorAsync(Samples.Jpeg(), name));
    }

    [Fact]
    public void Policy_without_types_fails_at_startup()
    {
        var e = Assert.Throws<InvalidOperationException>(() => new UploadGuardOptions().AddPolicy("empty", p => p.MaxSize(1)));
        Assert.Contains("empty", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Duplicate_policy_fails_at_startup()
    {
        var options = new UploadGuardOptions().AddPolicy("a", p => p.AllowImages());

        Assert.Throws<ArgumentException>(() => options.AddPolicy("a", p => p.AllowImages()));
    }

    [Fact]
    public async Task Unknown_policy_throws()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Images.ValidateAsync(new MemoryStream(Samples.Jpeg()), "photo.jpg", null, "nope", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Non_seekable_stream_throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Images.ValidateAsync(new NonSeekableStream(Samples.Jpeg()), "photo.jpg", null, TestPipeline.Policy, TestContext.Current.CancellationToken));
    }

    private sealed class NonSeekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
    }
}
