using System.Diagnostics.Metrics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using UploadGuard.Detection;

namespace UploadGuard;

/// <summary>
/// Validates, scans, transforms and stores uploads by named policy. <c>AddUploadGuard</c> registers it as a singleton.
/// </summary>
/// <remarks>
/// Checks run in this order and stop at the first failure: empty, size, file name, content detection, extension
/// against content, allow-list, Content-Type against content, type-specific content checks, then every
/// <see cref="IUploadScanner"/>.
/// </remarks>
public sealed partial class UploadPipeline
{
    private static readonly Meter Meter = new("UploadGuard");
    private static readonly Counter<long> Uploads =
        Meter.CreateCounter<long>("uploadguard.uploads", "{file}", "Uploads checked, by policy, result and detected file type.");

    private readonly UploadGuardOptions _options;
    private readonly IUploadScanner[] _scanners;
    private readonly IUploadStorage? _storage;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance. Dependency injection fills the optional services when they are registered.</summary>
    /// <param name="options">The policies.</param>
    /// <param name="scanners">Scanners that run after the built-in checks.</param>
    /// <param name="storage">Where <see cref="SaveAsync(IFormFile, string, CancellationToken)"/> stores files.</param>
    /// <param name="logger">Logs rejections and scanner failures.</param>
    public UploadPipeline(
        UploadGuardOptions options,
        IEnumerable<IUploadScanner>? scanners = null,
        IUploadStorage? storage = null,
        ILogger<UploadPipeline>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _scanners = [.. scanners ?? []];
        _storage = storage;
        _logger = logger ?? (ILogger)NullLogger.Instance;
    }

    /// <summary>Validates an uploaded file.</summary>
    /// <param name="file">The file.</param>
    /// <param name="policy">The policy name.</param>
    /// <param name="cancellationToken">Cancels the validation.</param>
    /// <returns>The result; check <see cref="UploadResult.IsValid"/>.</returns>
    /// <exception cref="InvalidOperationException">No policy has this name.</exception>
    public async Task<UploadResult> ValidateAsync(IFormFile file, string policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        await using var content = file.OpenReadStream();
        return await ValidateAsync(content, file.FileName, file.ContentType, policy, cancellationToken);
    }

    /// <summary>Validates content from any source.</summary>
    /// <param name="content">The content. It must be seekable; it is read several times and left open.</param>
    /// <param name="fileName">The client's file name.</param>
    /// <param name="contentType">The client's Content-Type, or null.</param>
    /// <param name="policy">The policy name.</param>
    /// <param name="cancellationToken">Cancels the validation.</param>
    /// <returns>The result; check <see cref="UploadResult.IsValid"/>.</returns>
    /// <exception cref="InvalidOperationException">No policy has this name.</exception>
    public async Task<UploadResult> ValidateAsync(
        Stream content, string fileName, string? contentType, string policy, CancellationToken cancellationToken = default)
    {
        var rules = GetPolicy(policy);
        CheckSeekable(content);
        var result = await ValidateCoreAsync(content, fileName, contentType, rules, cancellationToken);
        Record(policy, result);
        return result;
    }

    /// <summary>Validates an uploaded file, runs the policy's transforms and stores it under a generated name.</summary>
    /// <param name="file">The file.</param>
    /// <param name="policy">The policy name.</param>
    /// <param name="cancellationToken">Cancels the work.</param>
    /// <returns>The result; <see cref="UploadResult.StoredName"/> is set when it is valid.</returns>
    /// <exception cref="InvalidOperationException">No policy has this name, or no <see cref="IUploadStorage"/> is registered.</exception>
    public async Task<UploadResult> SaveAsync(IFormFile file, string policy, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        await using var content = file.OpenReadStream();
        return await SaveAsync(content, file.FileName, file.ContentType, policy, cancellationToken);
    }

    /// <summary>Validates content from any source, runs the policy's transforms and stores it under a generated name.</summary>
    /// <param name="content">The content. It must be seekable; it is read several times and left open.</param>
    /// <param name="fileName">The client's file name.</param>
    /// <param name="contentType">The client's Content-Type, or null.</param>
    /// <param name="policy">The policy name.</param>
    /// <param name="cancellationToken">Cancels the work.</param>
    /// <returns>The result; <see cref="UploadResult.StoredName"/> is set when it is valid.</returns>
    /// <exception cref="InvalidOperationException">No policy has this name, or no <see cref="IUploadStorage"/> is registered.</exception>
    public async Task<UploadResult> SaveAsync(
        Stream content, string fileName, string? contentType, string policy, CancellationToken cancellationToken = default)
    {
        var rules = GetPolicy(policy);
        CheckSeekable(content);
        var storage = _storage ?? throw new InvalidOperationException(
            "No IUploadStorage is registered. Set UploadGuardOptions.StoragePath or register your own IUploadStorage.");

        var result = await ValidateCoreAsync(content, fileName, contentType, rules, cancellationToken);
        if (result.IsValid)
        {
            result = await TransformAndStoreAsync(content, result, rules, storage, cancellationToken);
        }

        Record(policy, result);
        return result;
    }

    internal UploadPolicy GetPolicy(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return _options.Policies.TryGetValue(name, out var policy)
            ? policy
            : throw new InvalidOperationException($"No upload policy named '{name}' is registered. Add it with UploadGuardOptions.AddPolicy.");
    }

    /// <summary>Validates every file in a form request. Returns errors by form field, or null when all are valid.</summary>
    internal async Task<Dictionary<string, string[]>?> ValidateFormAsync(HttpRequest request, string policy, CancellationToken cancellationToken)
    {
        if (!request.HasFormContentType)
        {
            return null;
        }

        var form = await request.ReadFormAsync(cancellationToken);
        Dictionary<string, List<string>>? errors = null;
        foreach (var file in form.Files)
        {
            var result = await ValidateAsync(file, policy, cancellationToken);
            if (result.Error is { } error)
            {
                errors ??= [];
                if (!errors.TryGetValue(file.Name, out var messages))
                {
                    errors[file.Name] = messages = [];
                }

                messages.Add(error.Message);
            }
        }

        return errors?.ToDictionary(e => e.Key, e => e.Value.ToArray());
    }

    private async Task<UploadResult> ValidateCoreAsync(
        Stream content, string fileName, string? contentType, UploadPolicy policy, CancellationToken cancellationToken)
    {
        var result = new UploadResult { FileName = fileName, Length = content.Length };
        if (content.Length == 0)
        {
            return result with { Error = new(UploadErrorCode.Empty, "The file is empty.") };
        }

        if (content.Length > policy.MaxSizeBytes)
        {
            return result with { Error = new(UploadErrorCode.TooLarge, $"The file is larger than {policy.MaxSizeBytes} bytes.") };
        }

        if (FileNameValidator.Check(fileName) is { } nameError)
        {
            return result with { Error = new(UploadErrorCode.InvalidFileName, nameError) };
        }

        var candidates = await FileDetector.DetectAsync(content, cancellationToken);
        if (candidates.Length == 0)
        {
            return result with { Error = new(UploadErrorCode.UnknownType, "The file content is not a recognized file type.") };
        }

        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        var type = Array.Find(candidates, c => c.Extensions.Contains(extension));
        if (type is null)
        {
            var shown = extension.Length == 0 ? "no extension" : $"the extension '{extension}'";
            return result with
            {
                FileType = candidates[0],
                Error = new(UploadErrorCode.ExtensionMismatch, $"The file has {shown}, but the content was detected as {candidates[0].Name}."),
            };
        }

        result = result with { FileType = type };
        if (!policy.AllowedTypes.Contains(type))
        {
            return result with { Error = new(UploadErrorCode.TypeNotAllowed, $"{type.Name} files are not allowed here.") };
        }

        if (!ContentTypeMatches(contentType, type))
        {
            return result with { Error = new(UploadErrorCode.ContentTypeMismatch, $"The Content-Type does not match the content ({type.Name}).") };
        }

        if (await ContentInspector.InspectAsync(content, type, policy, cancellationToken) is { } contentError)
        {
            return result with { Error = contentError };
        }

        foreach (var scanner in _scanners)
        {
            content.Position = 0;
            try
            {
                await scanner.ScanAsync(content, type, cancellationToken);
            }
            catch (UploadRejectedException e)
            {
                return result with { Error = e.Error };
            }
            catch (Exception e) when (!cancellationToken.IsCancellationRequested)
            {
                LogScanFailed(_logger, e, scanner.GetType().Name);
                return result with { Error = new(UploadErrorCode.ScanFailed, "The file could not be scanned for malware.") };
            }
        }

        return result;
    }

    private static async Task<UploadResult> TransformAndStoreAsync(
        Stream content, UploadResult result, UploadPolicy policy, IUploadStorage storage, CancellationToken cancellationToken)
    {
        var type = result.FileType!;
        var current = content;
        MemoryStream? owned = null;
        try
        {
            foreach (var transformer in policy.Transformers)
            {
                current.Position = 0;
                var output = new MemoryStream();
                FileType? outputType;
                try
                {
                    outputType = await transformer.TransformAsync(current, type, output, cancellationToken);
                }
                catch (UploadRejectedException e)
                {
                    await output.DisposeAsync();
                    return result with { Error = e.Error };
                }

                if (outputType is null)
                {
                    await output.DisposeAsync();
                    continue;
                }

                if (owned is not null)
                {
                    await owned.DisposeAsync();
                }

                owned = output;
                current = output;
                type = outputType;
            }

            current.Position = 0;
            var name = await storage.SaveAsync(current, type, cancellationToken);
            return result with { FileType = type, Length = current.Length, StoredName = name };
        }
        finally
        {
            if (owned is not null)
            {
                await owned.DisposeAsync();
            }
        }
    }

    // Clients may omit the type or send application/octet-stream. Anything else must name the detected type.
    private static bool ContentTypeMatches(string? contentType, FileType type)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return true;
        }

        var media = contentType.AsSpan();
        var parameters = media.IndexOf(';');
        if (parameters >= 0)
        {
            media = media[..parameters];
        }

        media = media.Trim();
        if (media.Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        foreach (var mimeType in type.MimeTypes)
        {
            if (media.Equals(mimeType, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static void CheckSeekable(Stream content)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (!content.CanSeek)
        {
            throw new ArgumentException("The content must be seekable. Buffer it to a file first; IFormFile streams already are.", nameof(content));
        }
    }

    private void Record(string policy, UploadResult result)
    {
        Uploads.Add(
            1,
            new KeyValuePair<string, object?>("uploadguard.policy", policy),
            new KeyValuePair<string, object?>("uploadguard.result", result.Error?.Code.ToString() ?? "Accepted"),
            new KeyValuePair<string, object?>("uploadguard.file_type", result.FileType?.Name));

        if (result.Error is { } error)
        {
            LogRejected(_logger, policy, error.Code, error.Message);
        }
    }

    [LoggerMessage(1, LogLevel.Information, "Upload rejected by policy {Policy}: {Code}. {Reason}")]
    private static partial void LogRejected(ILogger logger, string policy, UploadErrorCode code, string reason);

    [LoggerMessage(2, LogLevel.Error, "Upload scanner {Scanner} failed; the file was rejected")]
    private static partial void LogScanFailed(ILogger logger, Exception exception, string scanner);
}
