# Security model

UploadGuard sits between `IFormFile` and your storage. It decides whether a file is what it claims to be and whether it carries active content, and it stores accepted files where they cannot be executed or traversed. It does not make an untrusted file safe to open in every program.

## Threat model

| Threat | Example | Mitigation | Where |
|---|---|---|---|
| Executable upload behind a harmless extension | `shell.php` renamed `cat.jpg`, `invoice.pdf.exe` | Type from content only; extension must belong to that type; executable inner extensions rejected | `FileDetector`, `FileNameValidator` |
| Stored XSS through a file the browser renders | HTML named `.txt`, SVG with `<script>`, HTML in an image | HTML sniffed like browsers do; SVG script checks; markup scan in images; serve with `nosniff`, `attachment` and a sandbox CSP | `FileDetector.ClassifyText`, `SvgInspector`, `ContentInspector`, README |
| Polyglot files | GIFAR, JPEG + PHP, GIF/JS | Markup scan in images; re-encoding with UploadGuard.PixelForge removes everything that is not pixels | `ContentInspector`, `ImageReencoder` |
| Macro malware | DOCM renamed DOCX, XLS with VBA, ODT with Basic | Macro-enabled OOXML is its own type; VBA project in compound files; ODF `Basic/` and `Scripts/` | `ArchiveInspector`, `ContentInspector` |
| Malicious PDF | `/OpenAction` running JavaScript, `/Launch`, embedded EXE | Name scan with `#xx` decoding, also inside FlateDecode object streams | `PdfInspector` |
| Decompression bombs | 42.zip, overlapping-entry bombs, GZIP of zeros, 50000×50000 PNG | Entry count, total size and ratio limits; GZIP unpacked to the limit only; PDF inflation budget; pixel limit before decoding | `ArchiveInspector`, `PdfInspector`, `ImageReencoder` |
| Path traversal | `../../app/web.config` as a file name or a ZIP entry | Client names never used as paths; storage accepts only generated names; zip slip entries rejected | `FileSystemUploadStorage`, `ArchiveInspector` |
| Name tricks | NUL bytes, `file.asp::$DATA`, `CON.jpg`, right-to-left override, trailing dots | Rejected by the file name rules | `FileNameValidator` |
| Known malware | EICAR, commodity droppers | ClamAV `INSTREAM`; scanner errors fail closed | `UploadGuard.ClamAV` |
| Privacy leaks | GPS coordinates in photo EXIF | Re-encoding writes no metadata | `ImageReencoder` |
| Denial of service through validation | Huge text files, many ZIP entries | `MaxSize` is checked first; every scan streams in 64 KB chunks with bounded memory | `UploadPipeline`, `ByteScanner` |

## OWASP File Upload Cheat Sheet

How each recommendation of the [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) maps to UploadGuard. "App" means it is your application's responsibility.

| Cheat sheet section | Recommendation | UploadGuard |
|---|---|---|
| Extension Validation | Validate after decoding the name; handle double extensions, null bytes, case, alternative handler extensions (`.phtml`, `.php5`), NTFS alternate data streams; reject colons | ✅ `InvalidFileName` (inner executable extensions, NUL, `:`, control characters), case-insensitive extension match |
| List Allowed Extensions | Allow only the extensions the business needs | ✅ Policies are allow-lists of types; each type has a fixed set of extensions |
| Block Extensions | A weak protection on its own | ✅ Not relied on: everything outside the allow-list is rejected |
| Content-Type Validation | Do not trust the header; use it as a quick check against an allow-list | ✅ `ContentTypeMismatch` when the header names another type |
| File Signature Validation | Check signatures with the Content-Type, but not on their own | ✅ Signatures are step 4 of 9, followed by structural and content checks |
| Filename Safety | Generate the name (UUID); if names are kept, limit length and characters, block leading periods, sequential periods and leading hyphens or spaces | ✅ Random 128-bit names in storage; the client name is validated with these rules for display |
| File Content Validation | Rewrite images; validate Office files; avoid ZIP; sandbox or review; hash scanning | ✅ Image rewriting (UploadGuard.PixelForge), Office macro and structure checks, ZIP limits; antivirus via `IUploadScanner`. Manual review and reporting: app |
| File Storage Location | Another host, else outside the web root; no per-directory config overrides; map IDs to files through a handler | ✅ Refuses a storage folder inside the web root; generated names only; serving through a handler (see README). Separate host: app |
| User Permissions | Authenticate uploaders; authorize access | App (`RequireAuthorization()`) |
| Filesystem Permissions | Least privilege; no execute | App. Stored files are created without execute permission by default; keep the folder non-executable |
| Upload and Download Limits | Size limits, including after decompression; download rate limits | ✅ `MaxSize`, `LimitArchives`, PDF inflation budget, pixel limit. Rate limiting: app (`AddRateLimiter`) |
| Introduction | Antivirus or sandbox | ✅ UploadGuard.ClamAV, `IUploadScanner` |
| Introduction | CDR for applicable types | ✅ Images. Documents: plug a CDR service in as an `IUploadTransformer` |
| Introduction | Keep libraries up to date | Dependabot in this repository; no runtime dependencies in the core |
| Introduction | Protect uploads from CSRF | App: keep ASP.NET Core antiforgery on for cookie-authenticated endpoints |

## What is not covered

- **PDF and legacy Office are scanned, not parsed.** The PDF check decodes `#xx` escapes and inflates FlateDecode streams, but not LZW, ASCIIHex or encrypted streams. The VBA check in DOC/XLS/PPT looks for the VBA project directory name; PowerPoint 97 can store VBA elsewhere. Use antivirus as well, and never open user PDFs inline on your own origin.
- **Archives are inspected one level deep.** A ZIP inside a ZIP is not unpacked. 7z, RAR and TAR are recognized but not inspected. Unpack archives with the same limits if you process their contents.
- **Declared ZIP sizes are trusted.** .NET's `ZipArchive` never inflates an entry past its declared size and other tools fail on the mismatch, so this is safe when you unpack with them. A custom inflater that ignores the declared size is not protected.
- **ZIP central directory size.** `ZipArchive` reads the whole central directory before entries can be counted; `MaxSize` bounds it.
- **Only images are rebuilt.** Documents and media are stored as uploaded; their content can still exploit a vulnerable viewer.
- **Text formats are not validated beyond encoding.** CSV formula injection (`=HYPERLINK(...)`) and XML external entities are problems for the code that reads the file. Disable DTD processing when you parse uploaded XML.
- **HEIC, AVIF, TIFF and media files** are checked by signature and for embedded markup only.

Found a gap? See [SECURITY.md](../SECURITY.md).
