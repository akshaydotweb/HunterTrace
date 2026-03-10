# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

We take the security of HunterTrace seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report vulnerabilities through one of these channels:

1. **GitHub Private Vulnerability Reporting**: Use the [Security Advisories](https://github.com/akshaydotweb/HunterTrace/security/advisories/new) tab to privately report a vulnerability.
2. **Email**: Send a detailed report to **akshayvmudaliar@gmail.com** with the subject line `[SECURITY] HunterTrace Vulnerability Report`.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Action | Timeframe |
| ------ | --------- |
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix & advisory | 30 days (critical), 90 days (non-critical) |

### What to Expect

- You will receive an acknowledgement within 48 hours.
- We will work with you to understand the scope and impact.
- A fix will be developed and tested privately.
- A security advisory will be published along with the patched release.
- Credit will be given to the reporter (unless anonymity is requested).

## Security Design Principles

HunterTrace follows these security practices:

- **No credential storage**: API keys are read exclusively from environment variables, never hardcoded or logged.
- **Input validation**: Email file inputs are parsed using Python's standard `email` library with strict boundary handling.
- **No outbound data exfiltration**: The tool only queries public IP geolocation/DNS APIs. No user data is sent to third-party services.
- **No code execution**: Email content is parsed, never executed. Attachments are not opened or run.
- **Dependency minimisation**: Only well-maintained, audited dependencies (NetworkX, NumPy, Requests) are used.

## Scope

The following are **in scope** for security reports:

- Code injection through crafted `.eml` files
- Information disclosure through output files or logs
- Dependency vulnerabilities in direct dependencies
- Credential leakage through CLI output or report files

The following are **out of scope**:

- Vulnerabilities in upstream API services (e.g., ip-api.com)
- Social engineering attacks
- Denial of service through large input files (this is a local CLI tool)
