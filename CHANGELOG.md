# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First release.

### Added

- **UploadGuard**
  - Content detection for 47 types from their bytes: images, PDF, Office (with and without macros), OpenDocument, text, CSV, XML, HTML, archives, audio, video and executables.
  - Named allow-list policies: `AddUploadGuard(o => o.AddPolicy("avatars", p => p.AllowImages().MaxSize(...)))`, checked at startup.
  - File name rules: paths, colons, control and invisible formatting characters, leading dots and hyphens, consecutive dots, device names, executable inner extensions.
  - Extension and Content-Type checks against the detected type.
  - Content checks: ZIP bomb and zip slip limits, encrypted ZIP entries, Office and OpenDocument macros, PDF JavaScript and other active content (including inside FlateDecode object streams), SVG scripts, script markup in images, GZIP bombs.
  - `UploadPipeline.ValidateAsync` and `SaveAsync` for `IFormFile` and seekable streams.
  - `WithUploadPolicy` endpoint filter for Minimal APIs and `[UploadPolicy]` for MVC, returning validation problem details.
  - `IUploadScanner`, `IUploadTransformer` and `IUploadStorage` extension points; scanners fail closed.
  - `FileSystemUploadStorage` with random names, refusing a folder inside the web root.
  - `uploadguard.uploads` metric and rejection logging.
- **UploadGuard.ClamAV**
  - Async `ClamAVClient` with `PingAsync`, `GetVersionAsync` and `ScanAsync` (`INSTREAM`), with timeouts.
  - `AddUploadGuardClamAV` scanner registration and an `AddClamAV` health check.
- **UploadGuard.PixelForge**
  - `ReencodeImages` re-encodes JPEG, PNG, GIF, BMP and WebP, removing metadata and appended data, with a pixel limit checked before decoding.

[0.1.0]: https://github.com/GrantTotinov/UploadGuard/releases/tag/v0.1.0
