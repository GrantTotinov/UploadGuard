using PixelForge;

namespace UploadGuard;

/// <summary>Adds image re-encoding to a policy.</summary>
public static class PixelForgeUploadPolicyExtensions
{
    /// <summary>
    /// Decodes every accepted image and encodes it again (content disarm and reconstruction). The stored file holds
    /// only pixels: EXIF, GPS, XMP, comments, appended data and polyglot payloads are gone, and the image is
    /// rotated upright first. JPEG and WebP stay in their format; PNG, GIF and BMP become PNG (GIF keeps its first frame).
    /// Other image types are rejected; non-image types pass through unchanged.
    /// </summary>
    /// <param name="policy">The policy.</param>
    /// <param name="maxPixels">The largest width × height to decode, checked from the header before allocating. Defaults to 40 MP.</param>
    /// <param name="quality">JPEG and lossy WebP quality from 1 to 100. Defaults to 90.</param>
    /// <returns>The policy.</returns>
    public static UploadPolicy ReencodeImages(this UploadPolicy policy, long maxPixels = 40_000_000, int quality = 90)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxPixels);
        ArgumentOutOfRangeException.ThrowIfLessThan(quality, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(quality, 100);
        return policy.Transform(new ImageReencoder(maxPixels, quality));
    }
}

internal sealed class ImageReencoder(long maxPixels, int quality) : IUploadTransformer
{
    public async Task<FileType?> TransformAsync(Stream input, FileType type, Stream output, CancellationToken cancellationToken)
    {
        if (!type.MimeType.StartsWith("image/", StringComparison.Ordinal))
        {
            return null;
        }

        var target = type == FileTypes.Jpeg || type == FileTypes.Webp ? type
            : type == FileTypes.Png || type == FileTypes.Gif || type == FileTypes.Bmp ? FileTypes.Png
            : throw new UploadRejectedException(new(UploadErrorCode.TypeNotAllowed, $"{type.Name} files cannot be re-encoded."));

        var lossless = type == FileTypes.Webp && await IsLosslessWebpAsync(input, cancellationToken);
        try
        {
            using var image = await Image.LoadAsync(input, new DecoderOptions { MaxPixels = maxPixels }, cancellationToken);
            image.Mutate(x => x.AutoOrient());
            if (target == FileTypes.Jpeg)
            {
                await image.SaveAsJpegAsync(output, quality, cancellationToken);
            }
            else if (target == FileTypes.Webp)
            {
                await image.SaveAsWebpAsync(output, quality, lossless, cancellationToken);
            }
            else
            {
                await image.SaveAsPngAsync(output, cancellationToken);
            }
        }
        catch (ImageTooLargeException e)
        {
            throw new UploadRejectedException(new(UploadErrorCode.TooLarge, e.Message));
        }
        catch (ImageFormatException)
        {
            throw new UploadRejectedException(new(UploadErrorCode.Corrupt, "The image data is damaged."));
        }

        return target;
    }

    // A lossless WebP has a VP8L chunk; keep it lossless instead of degrading screenshots and line art.
    private static async Task<bool> IsLosslessWebpAsync(Stream input, CancellationToken cancellationToken)
    {
        var header = new byte[64];
        var read = await input.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken);
        input.Position = 0;
        return header.AsSpan(0, read).IndexOf("VP8L"u8) >= 0;
    }
}
