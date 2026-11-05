using System.Diagnostics;
using System.IO.Compression;
using System.Xml.Linq;

namespace UploadGuard.Tests;

public sealed class PackageTests : IDisposable
{
    private readonly string _output = Directory.CreateTempSubdirectory("uploadguard-pack-").FullName;

    public void Dispose() => Directory.Delete(_output, recursive: true);

    [Theory]
    [InlineData("UploadGuard", "")]
    [InlineData("UploadGuard.ClamAV", "UploadGuard")]
    [InlineData("UploadGuard.PixelForge", "PixelForge,UploadGuard")]
    public void Package_has_only_the_expected_dependencies_and_files(string id, string expectedDependencies)
    {
        using var package = ZipFile.OpenRead(Pack(id));
        var entries = package.Entries.Select(e => e.FullName).ToHashSet();
        using var nuspecStream = package.Entries.Single(e => e.FullName.EndsWith(".nuspec", StringComparison.Ordinal)).Open();
        var metadata = XDocument.Load(nuspecStream).Root!.Elements().Single(e => e.Name.LocalName == "metadata");
        string Value(string name) => metadata.Elements().Single(e => e.Name.LocalName == name).Value;

        var group = Assert.Single(metadata.Elements().Single(e => e.Name.LocalName == "dependencies").Elements());
        Assert.Equal("net10.0", group.Attribute("targetFramework")!.Value);
        var dependencies = string.Join(',', group.Elements().Select(e => e.Attribute("id")!.Value).Order(StringComparer.Ordinal));
        Assert.Equal(expectedDependencies, dependencies);

        Assert.Equal("MIT", Value("license"));
        Assert.Equal("icon.png", Value("icon"));
        Assert.Equal("README.md", Value("readme"));
        Assert.Contains($"lib/net10.0/{id}.dll", entries);
        Assert.Contains($"lib/net10.0/{id}.xml", entries);
        Assert.Contains("icon.png", entries);
        Assert.Contains("README.md", entries);
    }

    private string Pack(string id)
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "UploadGuard.slnx")))
        {
            root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("Repository root not found.");
        }

        var configuration = AppContext.BaseDirectory.Contains($"{Path.DirectorySeparatorChar}Release{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            ? "Release"
            : "Debug";
        var project = Path.Combine(root, "src", id, $"{id}.csproj");
        var start = new ProcessStartInfo("dotnet", ["pack", project, "-c", configuration, "--no-build", "-o", _output])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"dotnet pack failed:\n{output.Result}\n{error.Result}");

        return Directory.GetFiles(_output, $"{id}.*.nupkg").Single(p => !p.EndsWith(".snupkg", StringComparison.Ordinal) && Path.GetFileName(p)[id.Length + 1] is >= '0' and <= '9');
    }
}
