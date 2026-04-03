# Security Policy

## Supported Versions

The following versions of **fortinet-mcp-server** currently receive security fixes:

| Version | Supported |
|---------|-----------|
| `1.x` (latest `master`) | ✅ |
| Older releases | ❌ |

We recommend always running the latest commit on `master`.

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**  
Doing so would expose the vulnerability before a fix is available.

### Preferred channel — GitHub Private Security Advisories

1. Go to the **[Security tab](https://github.com/paoloamato2/fortinet-mcp-server/security)** of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the advisory form with as much detail as possible (see below).
4. Submit — only the maintainer can see the report until it is disclosed.

GitHub's private advisory system guarantees end-to-end encryption and allows coordinated disclosure with a CVE if appropriate.

---

## What to Include in Your Report

To help us reproduce and fix the issue as quickly as possible, please provide:

- **Description** — a clear summary of the vulnerability and its potential impact.
- **Affected component** — which file / tool / function is involved.
- **Steps to reproduce** — minimal reproduction scenario (no live credentials required).
- **Environment** — Python version, OS, MCP client, FortiOS version (if relevant).
- **Suggested fix** (optional) — if you already have an idea of how to address it.

> **Never include real API tokens, credentials, or private IP addresses in your report.** Use placeholder values such as `YOUR_TOKEN_HERE` or `192.0.2.1`.

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within **48 hours** |
| Initial assessment | Within **5 business days** |
| Fix / mitigation | Within **30 days** (severity-dependent) |
| Public disclosure | After the fix is released, coordinated with the reporter |

---

## Scope

The following are **in scope**:

- Remote or local code execution via crafted MCP tool inputs.
- Credential or API token leakage through server output, logs, or error messages.
- Bypass of SSL verification in a way that silently weakens security.
- Dependency vulnerabilities with a direct, exploitable impact on this project.

The following are **out of scope**:

- Vulnerabilities in FortiGate firmware itself (report directly to [Fortinet PSIRT](https://www.fortinet.com/corporate/about-us/product-security/vulnerabilities-responsible-disclosure)).
- Issues that require physical access to the machine running the server.
- Denial-of-service attacks that require a valid API token (the token bearer already has full access).

---

## Responsible Disclosure Policy

We follow [coordinated vulnerability disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html). After a fix is released we will:

1. Credit the reporter in the release notes (unless they prefer to stay anonymous).
2. Publish a GitHub Security Advisory with a CVE if appropriate.

Thank you for helping keep **fortinet-mcp-server** and its users safe!
