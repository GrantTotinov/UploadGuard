using Microsoft.AspNetCore.StaticFiles;
using UploadGuard;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(kestrel => kestrel.Limits.MaxRequestBodySize = 25 * 1024 * 1024);

builder.Services.AddUploadGuard(o =>
{
    // Outside wwwroot: UploadGuard refuses to start if this is inside the web root.
    o.StoragePath = Path.Combine(builder.Environment.ContentRootPath, "App_Data", "uploads");

    o.AddPolicy("avatars", p => p
        .AllowImages()
        .MaxSize(5 * 1024 * 1024)
        .ReencodeImages(maxPixels: 25_000_000)); // UploadGuard.PixelForge: strips EXIF/GPS and polyglot payloads

    o.AddPolicy("documents", p => p
        .Allow(FileTypes.Pdf, FileTypes.Docx, FileTypes.Xlsx)
        .MaxSize(20 * 1024 * 1024));

    o.AddPolicy("imports", p => p
        .Allow(FileTypes.Csv)
        .MaxSize(2 * 1024 * 1024));
});

// Optional antivirus: docker run -d -p 3310:3310 clamav/clamav:stable, then run with ClamAV__Host=localhost.
var health = builder.Services.AddHealthChecks();
if (builder.Configuration["ClamAV:Host"] is { } clamAVHost)
{
    builder.Services.AddUploadGuardClamAV(o => o.Host = clamAVHost);
    health.AddClamAV();
}

var app = builder.Build();

app.MapGet("/", () => "UploadGuard sample. POST a form field 'file' to /avatars, /documents or /imports.");
app.MapHealthChecks("/healthz");

// Validate, re-encode and store in one call.
app.MapPost("/avatars", async (IFormFile file, UploadPipeline uploads, CancellationToken ct) =>
{
    var result = await uploads.SaveAsync(file, "avatars", ct);
    return result.IsValid
        ? Results.Created($"/files/{result.StoredName}", new { result.StoredName, Type = result.FileType!.Name, result.Length })
        : Invalid(file, result);
}).DisableAntiforgery(); // a token-authenticated API; keep antiforgery on for cookie-authenticated forms

app.MapPost("/documents", async (IFormFile file, UploadPipeline uploads, CancellationToken ct) =>
{
    var result = await uploads.SaveAsync(file, "documents", ct);
    return result.IsValid
        ? Results.Created($"/files/{result.StoredName}", new { result.StoredName, Type = result.FileType!.Name, result.Length })
        : Invalid(file, result);
}).DisableAntiforgery();

// Validate only: the filter rejects bad files before the handler reads them.
app.MapPost("/imports", async (IFormFile file, CancellationToken ct) =>
{
    using var reader = new StreamReader(file.OpenReadStream());
    var rows = 0;
    while (await reader.ReadLineAsync(ct) is not null)
    {
        rows++;
    }

    return Results.Ok(new { rows });
}).WithUploadPolicy("imports").DisableAntiforgery();

// Serve stored files so a browser never runs them: download only, no sniffing, sandboxed.
app.MapGet("/files/{name}", async (string name, IUploadStorage storage, HttpContext http, CancellationToken ct) =>
{
    Stream content;
    try
    {
        content = await storage.OpenReadAsync(name, ct);
    }
    catch (Exception e) when (e is ArgumentException or FileNotFoundException)
    {
        return Results.NotFound();
    }

    http.Response.Headers.XContentTypeOptions = "nosniff";
    http.Response.Headers.ContentSecurityPolicy = "default-src 'none'; sandbox";
    var contentType = new FileExtensionContentTypeProvider().TryGetContentType(name, out var type) ? type : "application/octet-stream";
    return Results.File(content, contentType, fileDownloadName: name);
});

app.Run();

static IResult Invalid(IFormFile file, UploadResult result) =>
    Results.ValidationProblem(new Dictionary<string, string[]> { [file.Name] = [result.Error!.Message] });
