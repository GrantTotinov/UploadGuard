using System.Text;

namespace UploadGuard.Tests;

public sealed class PixelForgeTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("uploadguard-pf-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public async Task Jpeg_loses_exif_and_appended_data_but_stays_jpeg()
    {
        var jpeg = Samples.Concat(WithExif(Samples.Jpeg(64, 48), "GPS-SECRET-42.6977N"), Samples.Utf8("TRAILING-PAYLOAD"));

        var (result, stored) = await SaveAsync(p => p.AllowImages().ReencodeImages(), jpeg, "photo.jpg");

        Assert.Same(FileTypes.Jpeg, result.FileType);
        Assert.EndsWith(".jpg", result.StoredName, StringComparison.Ordinal);
        Assert.True(stored.AsSpan().StartsWith(new byte[] { 0xFF, 0xD8, 0xFF }));
        Assert.DoesNotContain("GPS-SECRET", Encoding.Latin1.GetString(stored), StringComparison.Ordinal);
        Assert.DoesNotContain("TRAILING-PAYLOAD", Encoding.Latin1.GetString(stored), StringComparison.Ordinal);
        Assert.Equal(stored.Length, result.Length);
    }

    [Theory]
    [InlineData("anim.gif")]
    [InlineData("image.bmp")]
    public async Task Gif_and_bmp_become_png(string name)
    {
        var data = Samples.All[FileTypes.All.Single(t => t.Extensions.Contains(Path.GetExtension(name)))].Data;

        var (result, stored) = await SaveAsync(p => p.Allow(FileTypes.Gif, FileTypes.Bmp).ReencodeImages(), data, name);

        Assert.Same(FileTypes.Png, result.FileType);
        Assert.EndsWith(".png", result.StoredName, StringComparison.Ordinal);
        Assert.True(stored.AsSpan().StartsWith(new byte[] { 0x89, 0x50, 0x4E, 0x47 }));
    }

    [Theory]
    [InlineData(true, "VP8L")]
    [InlineData(false, "VP8 ")]
    public async Task Webp_keeps_lossless_or_lossy(bool lossless, string chunk)
    {
        var (result, stored) = await SaveAsync(p => p.AllowImages().ReencodeImages(), Samples.Webp(lossless), "image.webp");

        Assert.Same(FileTypes.Webp, result.FileType);
        Assert.Contains(chunk, Encoding.ASCII.GetString(stored, 0, Math.Min(64, stored.Length)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Image_over_the_pixel_limit_is_rejected_before_decoding()
    {
        var (result, _) = await SaveAsync(p => p.AllowImages().ReencodeImages(maxPixels: 100), Samples.Jpeg(100, 100), "big.jpg");

        Assert.Equal(UploadErrorCode.TooLarge, result.Error?.Code);
        Assert.Null(result.StoredName);
    }

    [Fact]
    public async Task Damaged_image_is_rejected()
    {
        var garbage = new byte[2000];
        new Random(3).NextBytes(garbage);
        var jpeg = Samples.Concat([0xFF, 0xD8, 0xFF, 0xE0], garbage);

        var (result, _) = await SaveAsync(p => p.AllowImages().ReencodeImages(), jpeg, "broken.jpg");

        Assert.Equal(UploadErrorCode.Corrupt, result.Error?.Code);
    }

    [Fact]
    public async Task Image_types_without_an_encoder_are_rejected()
    {
        var (data, name) = Samples.All[FileTypes.Heic];

        var (result, _) = await SaveAsync(p => p.Allow(FileTypes.Heic).ReencodeImages(), data, name);

        Assert.Equal(UploadErrorCode.TypeNotAllowed, result.Error?.Code);
    }

    [Fact]
    public async Task Non_images_pass_through_unchanged()
    {
        var (data, name) = Samples.All[FileTypes.Pdf];

        var (result, stored) = await SaveAsync(p => p.AllowImages().Allow(FileTypes.Pdf).ReencodeImages(), data, name);

        Assert.Same(FileTypes.Pdf, result.FileType);
        Assert.Equal(data, stored);
    }

    [Theory]
    [InlineData(0, 90)]
    [InlineData(100, 0)]
    [InlineData(100, 101)]
    public void Invalid_arguments_throw(long maxPixels, int quality)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new UploadPolicy().ReencodeImages(maxPixels, quality));
    }

    private async Task<(UploadResult Result, byte[] Stored)> SaveAsync(Action<UploadPolicy> policy, byte[] data, string name)
    {
        var pipeline = TestPipeline.Create(policy, storage: new FileSystemUploadStorage(_root));
        var result = await pipeline.SaveAsync(new MemoryStream(data), name, null, TestPipeline.Policy, TestContext.Current.CancellationToken);
        var stored = result.StoredName is null ? [] : await File.ReadAllBytesAsync(Path.Combine(_root, result.StoredName), TestContext.Current.CancellationToken);
        return (result, stored);
    }

    // Inserts an EXIF APP1 segment (an empty big-endian IFD followed by the marker text) right after SOI.
    private static byte[] WithExif(byte[] jpeg, string marker)
    {
        var payload = Samples.Concat(Samples.Utf8("Exif\0\0"), [0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], Samples.Utf8(marker));
        var length = payload.Length + 2;
        return Samples.Concat(jpeg[..2], [0xFF, 0xE1, (byte)(length >> 8), (byte)length], payload, jpeg[2..]);
    }
}
