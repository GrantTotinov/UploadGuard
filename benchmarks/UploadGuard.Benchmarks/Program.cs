using BenchmarkDotNet.Running;
using UploadGuard.Benchmarks;

if (args.Contains("--compare"))
{
    Comparison.Print();
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(DetectionBenchmarks).Assembly).Run(args);
