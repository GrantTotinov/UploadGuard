# Security policy

## Supported versions

Only the latest release receives security fixes. Before 1.0, that is the latest `0.x` version.

## Reporting a vulnerability

Please do **not** open a public issue.

Report privately through GitHub: **Security → Report a vulnerability** on this repository ([private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).

Include:

- the UploadGuard package versions and the .NET version,
- the policy configuration,
- a minimal file or code that gets past a check, or crashes or hangs the validation,
- what you expected UploadGuard to reject.

You should get a reply within 7 days. Fixes ship as a patch release with a GitHub Security Advisory that credits you, unless you prefer otherwise.

A bypass of a documented check is a vulnerability. Something listed under "What is not covered" in [docs/security.md](docs/security.md) is a feature request, but still welcome in private if it is exploitable.
