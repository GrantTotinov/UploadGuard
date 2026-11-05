using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace UploadGuard.Tests;

public sealed class AspNetCoreTests : IAsyncDisposable
{
    private readonly string _storage = Directory.CreateTempSubdirectory("uploadguard-web-").FullName;
    private WebApplication? _app;

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.DisposeAsync();
        }

        Directory.Delete(_storage, recursive: true);
    }

    [Fact]
    public async Task Endpoint_filter_lets_valid_files_through()
    {
        using var client = await StartAsync();

        using var response = await client.PostAsync("/avatar", Form(("file", Samples.Jpeg(), "me.jpg", "image/jpeg")), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("me.jpg", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Endpoint_filter_returns_a_validation_problem_per_field()
    {
        using var client = await StartAsync();
        var form = Form(
            ("file", Samples.Utf8("<?php echo 1; ?>"), "shell.jpg", "image/jpeg"),
            ("extra", Samples.Jpeg(), "ok.jpg", "image/jpeg"));

        using var response = await client.PostAsync("/avatar", form, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var problem = await response.Content.ReadFromJsonAsync<HttpValidationProblemDetails>(TestContext.Current.CancellationToken);
        var error = Assert.Single(problem!.Errors);
        Assert.Equal("file", error.Key);
        Assert.Contains("extension", Assert.Single(error.Value), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Endpoint_filter_with_an_unknown_policy_fails_at_startup()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            using var client = await StartAsync(app => app.MapPost("/x", (IFormFile file) => "x").WithUploadPolicy("missing").DisableAntiforgery());
            await client.GetAsync("/", TestContext.Current.CancellationToken);
        });
    }

    [Fact]
    public async Task Mvc_attribute_returns_a_validation_problem()
    {
        using var client = await StartAsync();

        using var response = await client.PostAsync("/mvc/avatar", Form(("file", Samples.All[FileTypes.Pdf].Data, "cv.pdf", "application/pdf")), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>(TestContext.Current.CancellationToken);
        Assert.Contains("not allowed", Assert.Single(problem!.Errors["file"]), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Mvc_attribute_lets_valid_files_through()
    {
        using var client = await StartAsync();

        using var response = await client.PostAsync("/mvc/avatar", Form(("file", Samples.Png(), "me.png", "image/png")), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SaveAsync_stores_through_dependency_injection()
    {
        using var client = await StartAsync();

        using var response = await client.PostAsync("/save", Form(("file", Samples.Jpeg(), "me.jpg", "image/jpeg")), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var name = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(File.Exists(Path.Combine(_storage, name)));
    }

    private async Task<HttpClient> StartAsync(Action<WebApplication>? map = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddControllers().AddApplicationPart(typeof(AvatarController).Assembly);
        builder.Services.AddUploadGuard(o =>
        {
            o.StoragePath = _storage;
            o.AddPolicy("avatars", p => p.AllowImages().MaxSize(1_000_000));
        });

        _app = builder.Build();
        if (map is not null)
        {
            map(_app);
        }
        else
        {
            _app.MapPost("/avatar", (IFormFile file) => file.FileName).WithUploadPolicy("avatars").DisableAntiforgery();
            _app.MapPost("/save", async (IFormFile file, UploadPipeline uploads, CancellationToken ct) =>
            {
                var result = await uploads.SaveAsync(file, "avatars", ct);
                return result.IsValid ? Results.Text(result.StoredName) : Results.BadRequest(result.Error);
            }).DisableAntiforgery();
            _app.MapControllers();
        }

        await _app.StartAsync(TestContext.Current.CancellationToken);
        return _app.GetTestClient();
    }

    private static MultipartFormDataContent Form(params (string Field, byte[] Data, string FileName, string ContentType)[] files)
    {
        var form = new MultipartFormDataContent();
        foreach (var (field, data, fileName, contentType) in files)
        {
            var content = new ByteArrayContent(data);
            content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
            form.Add(content, field, fileName);
        }

        return form;
    }
}

[ApiController]
[Route("mvc")]
public sealed class AvatarController : ControllerBase
{
    [HttpPost("avatar")]
    [UploadPolicy("avatars")]
    public IActionResult Upload(IFormFile file) => Ok(file.FileName);
}
