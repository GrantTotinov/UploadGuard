namespace UploadGuard.Tests;

public sealed class PipelineTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("uploadguard-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public async Task Scanner_runs_after_the_built_in_checks_and_sees_the_whole_file()
    {
        var scanner = new RecordingScanner();
        var pipeline = TestPipeline.Create(p => p.AllowImages(), [scanner]);
        var jpeg = Samples.Jpeg();

        Assert.True((await pipeline.CheckAsync(jpeg, "photo.jpg")).IsValid);
        Assert.Equal(jpeg, scanner.Seen);
        Assert.Same(FileTypes.Jpeg, scanner.Type);

        scanner.Seen = null;
        await pipeline.CheckAsync(Samples.Jpeg(), "photo.png");
        Assert.Null(scanner.Seen);
    }

    [Fact]
    public async Task Scanner_rejection_is_returned()
    {
        var scanner = new RecordingScanner { Throw = new UploadRejectedException(new(UploadErrorCode.Malware, "Infected.")) };
        var pipeline = TestPipeline.Create(p => p.AllowImages(), [scanner]);

        var result = await pipeline.CheckAsync(Samples.Jpeg(), "photo.jpg");

        Assert.Equal(new UploadError(UploadErrorCode.Malware, "Infected."), result.Error);
    }

    [Fact]
    public async Task Failing_scanner_fails_closed()
    {
        var scanner = new RecordingScanner { Throw = new System.Net.Sockets.SocketException() };
        var pipeline = TestPipeline.Create(p => p.AllowImages(), [scanner]);

        Assert.Equal(UploadErrorCode.ScanFailed, await pipeline.ErrorAsync(Samples.Jpeg(), "photo.jpg"));
    }

    [Fact]
    public async Task Cancellation_is_not_turned_into_a_rejection()
    {
        using var cancel = new CancellationTokenSource();
        var scanner = new RecordingScanner { OnScan = cancel.Cancel, Throw = new OperationCanceledException() };
        var pipeline = TestPipeline.Create(p => p.AllowImages(), [scanner]);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            pipeline.ValidateAsync(new MemoryStream(Samples.Jpeg()), "photo.jpg", null, TestPipeline.Policy, cancel.Token));
    }

    [Fact]
    public async Task SaveAsync_stores_under_a_random_name_with_the_detected_extension()
    {
        var storage = new FileSystemUploadStorage(_root);
        var pipeline = TestPipeline.Create(p => p.AllowImages(), storage: storage);
        var jpeg = Samples.Jpeg();

        var result = await pipeline.SaveAsync(new MemoryStream(jpeg), "My Photo.JPEG", "image/jpeg", TestPipeline.Policy, TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
        Assert.Matches("^[0-9a-f]{32}\\.jpg$", result.StoredName);
        Assert.Equal(jpeg, await File.ReadAllBytesAsync(Path.Combine(_root, result.StoredName!), TestContext.Current.CancellationToken));
        await using var stored = await storage.OpenReadAsync(result.StoredName!, TestContext.Current.CancellationToken);
        Assert.Equal(jpeg.Length, stored.Length);
    }

    [Fact]
    public async Task SaveAsync_does_not_store_rejected_files()
    {
        var pipeline = TestPipeline.Create(p => p.AllowImages(), storage: new FileSystemUploadStorage(_root));

        var result = await pipeline.SaveAsync(new MemoryStream(Samples.Jpeg()), "photo.exe", null, TestPipeline.Policy, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Null(result.StoredName);
        Assert.Empty(Directory.GetFiles(_root));
    }

    [Fact]
    public async Task SaveAsync_runs_transforms_and_stores_their_output()
    {
        var pipeline = TestPipeline.Create(p => p.AllowImages().Transform(new ToPng()), storage: new FileSystemUploadStorage(_root));

        var result = await pipeline.SaveAsync(new MemoryStream(Samples.Jpeg()), "photo.jpg", null, TestPipeline.Policy, TestContext.Current.CancellationToken);

        Assert.Same(FileTypes.Png, result.FileType);
        Assert.EndsWith(".png", result.StoredName, StringComparison.Ordinal);
        Assert.Equal(ToPng.Output, await File.ReadAllBytesAsync(Path.Combine(_root, result.StoredName!), TestContext.Current.CancellationToken));
        Assert.Equal(ToPng.Output.Length, result.Length);
    }

    [Fact]
    public async Task SaveAsync_without_storage_throws()
    {
        var pipeline = TestPipeline.Create(p => p.AllowImages());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            pipeline.SaveAsync(new MemoryStream(Samples.Jpeg()), "photo.jpg", null, TestPipeline.Policy, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("../secret.txt")]
    [InlineData("..\\secret.txt")]
    [InlineData("/etc/passwd")]
    [InlineData("0123456789abcdef0123456789abcdef.jpg/../../x")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF.jpg")]
    [InlineData("photo.jpg")]
    [InlineData("")]
    public async Task Storage_refuses_names_it_did_not_generate(string name)
    {
        var storage = new FileSystemUploadStorage(_root);

        await Assert.ThrowsAsync<ArgumentException>(() => storage.OpenReadAsync(name, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => storage.DeleteAsync(name, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Storage_deletes_stored_files()
    {
        var storage = new FileSystemUploadStorage(_root);
        var name = await storage.SaveAsync(new MemoryStream([1, 2, 3]), FileTypes.Png, TestContext.Current.CancellationToken);

        await storage.DeleteAsync(name, TestContext.Current.CancellationToken);

        Assert.Empty(Directory.GetFiles(_root));
    }

    [Theory]
    [InlineData("wwwroot")]
    [InlineData("wwwroot/uploads")]
    public void Storage_inside_the_web_root_fails_at_startup(string relative)
    {
        var webRoot = Path.Combine(_root, "wwwroot");

        Assert.Throws<InvalidOperationException>(() => FileSystemUploadStorage.Create(Path.Combine(_root, relative), webRoot + Path.DirectorySeparatorChar));
    }

    [Fact]
    public void Storage_next_to_the_web_root_is_fine()
    {
        var storage = FileSystemUploadStorage.Create(Path.Combine(_root, "wwwroot-uploads"), Path.Combine(_root, "wwwroot"));

        Assert.True(Directory.Exists(storage.Root));
    }

    private sealed class RecordingScanner : IUploadScanner
    {
        public byte[]? Seen { get; set; }

        public FileType? Type { get; private set; }

        public Exception? Throw { get; init; }

        public Action? OnScan { get; init; }

        public async Task ScanAsync(Stream content, FileType type, CancellationToken cancellationToken)
        {
            using var copy = new MemoryStream();
            await content.CopyToAsync(copy, cancellationToken);
            Seen = copy.ToArray();
            Type = type;
            OnScan?.Invoke();
            if (Throw is not null)
            {
                throw Throw;
            }
        }
    }

    private sealed class ToPng : IUploadTransformer
    {
        public static readonly byte[] Output = Samples.Png();

        public async Task<FileType?> TransformAsync(Stream input, FileType type, Stream output, CancellationToken cancellationToken)
        {
            await output.WriteAsync(Output, cancellationToken);
            return FileTypes.Png;
        }
    }
}
