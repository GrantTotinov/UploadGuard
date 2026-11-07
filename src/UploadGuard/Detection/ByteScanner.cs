using System.Buffers;

namespace UploadGuard.Detection;

internal enum ScanMode
{
    /// <summary>Byte-exact matching. Reported positions are exact.</summary>
    Exact,

    /// <summary>ASCII case-insensitive. Patterns must be lowercase.</summary>
    IgnoreCase,

    /// <summary>Decodes PDF name escapes (<c>/J#61vaScript</c>) before matching. Positions are approximate.</summary>
    PdfNames,
}

/// <summary>Searches a stream for byte patterns in fixed-size chunks, so files are never loaded whole.</summary>
internal static class ByteScanner
{
    private const int ChunkSize = 64 * 1024;

    /// <summary>Returns the index of the first pattern found from the current position, or -1.</summary>
    public static async Task<int> FindFirstAsync(Stream stream, byte[][] patterns, ScanMode mode, CancellationToken cancellationToken)
    {
        var found = -1;
        await ScanAsync(stream, patterns, mode, long.MaxValue, (index, _) =>
        {
            found = index;
            return false;
        }, cancellationToken);
        return found;
    }

    /// <summary>
    /// Reads at most <paramref name="maxBytes"/> from the current position and calls <paramref name="onMatch"/>
    /// with the pattern index and the match end (relative to the start position) until it returns false.
    /// </summary>
    /// <returns>The number of bytes read.</returns>
    public static async Task<long> ScanAsync(
        Stream stream, byte[][] patterns, ScanMode mode, long maxBytes, Func<int, long, bool> onMatch, CancellationToken cancellationToken)
    {
        var longest = patterns.Max(p => p.Length);
        var overlap = (mode == ScanMode.PdfNames ? longest * 3 : longest) - 1;
        var buffer = ArrayPool<byte>.Shared.Rent(ChunkSize + overlap);
        var work = mode == ScanMode.Exact ? null : ArrayPool<byte>.Shared.Rent(ChunkSize + overlap);
        try
        {
            long total = 0;
            var carried = 0;
            while (total < maxBytes)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(carried, (int)Math.Min(ChunkSize, maxBytes - total)), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                var length = carried + read;
                var windowStart = total - carried;
                total += read;
                if (!Search(buffer, work, length, carried, windowStart, patterns, mode, onMatch))
                {
                    break;
                }

                carried = Math.Min(overlap, length);
                Buffer.BlockCopy(buffer, length - carried, buffer, 0, carried);
            }

            return total;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            if (work is not null)
            {
                ArrayPool<byte>.Shared.Return(work);
            }
        }
    }

    private static bool Search(
        byte[] buffer, byte[]? work, int length, int carried, long windowStart, byte[][] patterns, ScanMode mode, Func<int, long, bool> onMatch)
    {
        ReadOnlySpan<byte> window = mode switch
        {
            ScanMode.Exact => buffer.AsSpan(0, length),
            ScanMode.IgnoreCase => ToLower(buffer.AsSpan(0, length), work!),
            _ => DecodePdfNames(buffer.AsSpan(0, length), work!),
        };

        // Matches that end inside the carried overlap were already reported from the previous chunk.
        // Transformed modes cannot map positions back, and their callers stop at the first match anyway.
        var reportedUpTo = mode == ScanMode.Exact ? carried : 0;
        for (var p = 0; p < patterns.Length; p++)
        {
            var from = 0;
            int index;
            while ((index = window[from..].IndexOf(patterns[p])) >= 0)
            {
                var end = from + index + patterns[p].Length;
                if (end > reportedUpTo && !onMatch(p, windowStart + end))
                {
                    return false;
                }

                from += index + 1;
            }
        }

        return true;
    }

    private static Span<byte> ToLower(ReadOnlySpan<byte> source, byte[] work)
    {
        for (var i = 0; i < source.Length; i++)
        {
            var b = source[i];
            work[i] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
        }

        return work.AsSpan(0, source.Length);
    }

    private static Span<byte> DecodePdfNames(ReadOnlySpan<byte> source, byte[] work)
    {
        var written = 0;
        for (var i = 0; i < source.Length; i++)
        {
            if (source[i] == '#' && i + 2 < source.Length && Hex(source[i + 1]) is var high and >= 0 && Hex(source[i + 2]) is var low and >= 0)
            {
                work[written++] = (byte)((high << 4) | low);
                i += 2;
            }
            else
            {
                work[written++] = source[i];
            }
        }

        return work.AsSpan(0, written);
    }

    private static int Hex(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => -1,
    };
}
