namespace UploadGuard.Tests;

/// <summary>
/// Hostile input must produce a rejection, never an exception: an exception is a 500 for the caller and often a
/// parser bug. Seeded, so failures reproduce.
/// </summary>
public sealed class FuzzTests
{
    [Fact]
    public async Task Random_bytes_never_throw()
    {
        var random = new Random(1234);
        var pipeline = TestPipeline.AllowAll();
        for (var i = 0; i < 2000; i++)
        {
            var data = new byte[random.Next(1, 600)];
            random.NextBytes(data);
            await pipeline.CheckAsync(data, "file.bin");
        }
    }

    [Fact]
    public async Task Mutated_samples_never_throw()
    {
        var random = new Random(5678);
        var pipeline = TestPipeline.AllowAll();
        foreach (var (data, name) in Samples.All.Values)
        {
            for (var i = 0; i < 150; i++)
            {
                var mutated = (byte[])data.Clone();
                var flips = random.Next(1, 8);
                for (var f = 0; f < flips; f++)
                {
                    mutated[random.Next(mutated.Length)] = (byte)random.Next(256);
                }

                if (random.Next(4) == 0)
                {
                    Array.Resize(ref mutated, random.Next(1, mutated.Length + 1));
                }

                await pipeline.CheckAsync(mutated, name);
            }
        }
    }
}
