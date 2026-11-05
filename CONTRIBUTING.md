# Contributing

Thanks for helping. UploadGuard is a security library, so it stays small and every check needs a test that proves it.

## Before you code

- **Bypasses:** report them privately, see [SECURITY.md](SECURITY.md).
- **Bugs:** open an issue with the policy and a minimal file (or the code that generates it).
- **New file types or checks:** open an issue first and describe the real use case.

## Rules

- No new runtime dependencies in `UploadGuard`. It depends only on the ASP.NET Core shared framework.
- Never read a whole file into memory. Use `ByteScanner` or a streaming reader with a limit.
- Hostile input must produce an `UploadError`, never an exception. `FuzzTests` checks this for every sample.
- Fail closed: when a check cannot finish, reject the file.
- Error messages go to clients: no paths, stack traces or signature names.
- Test files are generated in `tests/UploadGuard.Tests/Samples.cs`. Do not commit binary samples or real malware; use EICAR for antivirus tests.
- A new type needs an entry in `FileTypes`, a signature in `FileDetector`, and a sample in `Samples.All` (a test fails otherwise).

## Build and test

Requires the .NET 10 SDK.

```bash
dotnet build -warnaserror
dotnet test
dotnet format --verify-no-changes
```

All three must pass. CI also runs the tests against a real clamd container.

To run the ClamAV integration test locally:

```bash
docker run -d -p 3310:3310 clamav/clamav:stable
CLAMAV_HOST=localhost dotnet test
```

Comparison table and benchmarks:

```bash
dotnet run -c Release --project benchmarks/UploadGuard.Benchmarks -- --compare
dotnet run -c Release --project benchmarks/UploadGuard.Benchmarks -- --filter '*'
```

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat: ...`, `fix: ...`, `docs: ...`, `test: ...`, `chore: ...`.

## License

By contributing you agree that your contribution is licensed under the MIT License.
