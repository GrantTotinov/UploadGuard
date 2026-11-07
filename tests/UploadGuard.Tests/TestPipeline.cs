namespace UploadGuard.Tests;

internal static class TestPipeline
{
    public const string Policy = "test";

    public static UploadPipeline Create(Action<UploadPolicy> configure, IEnumerable<IUploadScanner>? scanners = null, IUploadStorage? storage = null) =>
        new(new UploadGuardOptions().AddPolicy(Policy, configure), scanners, storage);

    public static UploadPipeline AllowAll() => Create(p => p.Allow([.. FileTypes.All]));

    public static Task<UploadResult> CheckAsync(this UploadPipeline pipeline, byte[] data, string name, string? contentType = null) =>
        pipeline.ValidateAsync(new MemoryStream(data), name, contentType, Policy, TestContext.Current.CancellationToken);

    public static async Task<UploadErrorCode?> ErrorAsync(this UploadPipeline pipeline, byte[] data, string name, string? contentType = null) =>
        (await pipeline.CheckAsync(data, name, contentType)).Error?.Code;
}
