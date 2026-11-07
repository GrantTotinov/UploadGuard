using BenchmarkDotNet.Attributes;
using UploadGuard.Tests;

namespace UploadGuard.Benchmarks;

/// <summary>
/// Time to accept one valid upload. Mime-Detective and File.TypeChecker only match signatures; UploadGuard runs the
/// whole policy (name, signature, extension, Content-Type and the content checks for that type).
/// </summary>
[MemoryDiagnoser]
public class DetectionBenchmarks
{
    private static readonly UploadPipeline Pipeline = new(new UploadGuardOptions()
        .AddPolicy("p", p => p.AllowImages().Allow(FileTypes.Pdf, FileTypes.Docx).MaxSize(50_000_000)));

    private byte[] _data = [];
    private string _name = "";

    [Params("photo.jpg", "letter.docx", "invoice.pdf")]
    public string File { get; set; } = "";

    [GlobalSetup]
    public void Setup()
    {
        (_data, _name) = File switch
        {
            "photo.jpg" => (Samples.Jpeg(1920, 1080), File),
            "letter.docx" => (Samples.All[FileTypes.Docx].Data, File),
            _ => (Samples.PdfWithCompressedObject(new string('x', 200_000)), File),
        };
    }

    [Benchmark(Baseline = true)]
    public Task<UploadResult> UploadGuard() => Pipeline.ValidateAsync(new MemoryStream(_data), _name, null, "p");

    [Benchmark]
    public bool MimeDetective() => Detectors.MimeDetective(_data, _name).Accepted;

    [Benchmark]
    public bool FileTypeChecker() => Detectors.FileTypeChecker(_data, _name).Accepted;
}
