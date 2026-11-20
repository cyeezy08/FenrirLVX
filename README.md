# FenrirLVX

<div align="center">

**WordPress exposure intelligence with explicit evidence and coverage.**

[![FenrirLVX CI](https://github.com/cyeezy08/FenrirLVX/actions/workflows/ci.yml/badge.svg)](https://github.com/cyeezy08/FenrirLVX/actions/workflows/ci.yml)
[![Source](https://img.shields.io/badge/source-GitHub-111111?logo=github)](https://github.com/cyeezy08/FenrirLVX)
[![Go module](https://img.shields.io/badge/Go-module-00ADD8?logo=go)](go.mod)

[Quick start](#quick-start) · [How matching works](#how-matching-works) · [Understanding results](#understanding-results) · [Architecture](#architecture) · [Verification](#verification)

</div>

<p align="center">
  <img src="TUI.gif" alt="Recorded terminal interface for FenrirLVX" width="900">
</p>

FenrirLVX is a Go CLI for **authorized WordPress security reviews**. It identifies WordPress technologies, enumerates components found in responses, compares reported plugin versions with a local advisory database, and explains what the database could and could not assess.

The goal is not a reassuring green screen. It is a reviewable record of **what was detected, which advisory matched, which version evidence supported it, and what remained unknown**.

> **Scope:** Run active checks only against properties you own or have explicit written authorization to assess. An absence of matching advisories is not proof of a secure installation.

## What is implemented

| Component | Implementation | Evidence |
| :-- | :-- | :-- |
| WordPress fingerprinting | HTTP-derived technology fingerprints and component enumeration | `pkg/engine/fingerprint.go`, `pkg/engine/enum.go` |
| Local advisory lookup | Committed `vuln_db.json`, parsed into advisory ranges | `pkg/engine/vuln.go` |
| Version-aware matching | Lower and upper version bounds, inclusive/exclusive comparisons | `pkg/engine/semver.go` |
| Coverage accounting | Count detected components, matched database entries, missing entries and unknown ranges | `SummarizeCoverage` in `pkg/engine/vuln.go` |
| Finding evidence | Matching advisory, reported version, confidence flags and changelog signals | `pkg/engine/disclosure.go`, `pkg/engine/comfirm.go` |
| CLI workflow | Single-target `scan`, `wordpress`, `version`, and a legacy optional `mass` command | `cmd/` |
| Regression tests | Version-boundary, conversion and coverage tests | `pkg/engine/*test.go` |

The repository also contains an **optional legacy Shodan adapter**. That integration is not required for the basic `scan` command and is **not part of Leviathan X's proposed core intelligence corpus**. Keep third-party data and provider terms separate from a customer-owned asset inventory.

## Quick start

### Build from source

The repository declares **Go 1.27** in `go.mod`. Check your installed toolchain before building.

```bash
git clone https://github.com/cyeezy08/FenrirLVX.git
cd FenrirLVX
go build -o fenrir .
./fenrir version
./fenrir --help
```

### Run an authorized check

```bash
./fenrir scan --target https://staging.example.com
```

Use only a staging instance you administer or another explicitly authorized test environment.

The scanner loads `vuln_db.json` from the working directory. **Keep the JSON file beside your working directory when running the command.** No Shodan API key is required by `scan`.

### Read-only CLI inspection

```bash
./fenrir --help
./fenrir version
```

## How matching works

1. **Fingerprint:** identify the CMS and discover component slugs from available responses.
2. **Normalize:** map detected component names and versions into the local advisory database.
3. **Compare:** evaluate version ranges and inclusive/exclusive bounds.
4. **Explain:** report the matched advisory, detected version, and whether the range was unbounded or the version unverified.
5. **Account for missing information:** list components missing from the local database, components with unreadable versions, and advisories with incomplete range bounds.

**Important limitation:** current `parseSemver` converts non-numeric components to zero and does not implement every ecosystem-specific version syntax. Complex version strings need validation; uncertain comparisons should not be treated as verified exploitation.

## Understanding results

| Output | Meaning | What it does **not** mean |
| :-- | :-- | :-- |
| Matching advisory | A known local advisory range matched the reported component version | Exploitation was confirmed |
| Unknown or unreadable version | The version could not be evaluated reliably | The component is safe |
| Component missing from the local DB | The installed advisory data has no matching component entry | No advisory exists elsewhere |
| Unbounded advisory | A local range omits a lower or upper bound | Every affected version has been independently verified |
| No matching signature | Nothing in the available data matched | The site is vulnerability-free |

### Coverage example

```text
3 / 7 detected components represented in the local advisory database
4 components have no local advisory coverage
```

This is an **illustration of output semantics**, not a live scan or a claimed benchmark.

Offline advisory checks depend on the freshness, format and terms of the source dataset. The committed `vuln_db.json` is not automatically updated by running the scanner. If refreshing from a licensed source, validate the converted records before replacing the database.

## Architecture

```text
Customer-authorized site
       |
       v
HTTP technology fingerprints
       |
       +----> component slugs / detected versions
                    |
                    v
             local vuln_db.json
                    |
                    v
         bounded version matching
                    |
                    v
       evidence + coverage + uncertainty
                    |
                    v
              CLI review output
```

For the source structure, inspect `cmd/` (CLI), `pkg/engine/` (fingerprinting and correlation), `pkg/banner/` (terminal output), `pkg/shodan/` (optional legacy integration) and `tools/` (build/data conversion utilities).

FenrirLVX is a **standalone tool**. The future Leviathan X dashboard and ClickHouse store are separate architecture decisions, not existing Fenrir integrations.

## Verification

The repository includes Go tests and a GitHub Actions workflow. To check your checkout:

```bash
go test ./...
go vet ./...
go build ./...
```

Read the live [GitHub Actions runs](https://github.com/cyeezy08/FenrirLVX/actions/workflows/ci.yml) for CI outcomes. The presence of tests, workflows and badges **does not itself establish a passing run**.

### Known review items

- Validate complex WordPress plugin version strings and unusual advisory ranges before making definitive match claims.
- Review the optional `mass` path and its scope controls separately from the core single-target command.
- Check provider-specific data licensing and update timestamps for any imported advisory feed.
- Compare claimed CLI output and screenshots with fresh local captures when preparing a release.

## Responsible use and contact

Work only within an approved asset scope. Please report reproducible issues and limitations through [GitHub issues](https://github.com/cyeezy08/FenrirLVX/issues).

FenrirLVX is part of the [cyeezy08 engineering portfolio](https://github.com/cyeezy08), and its concepts may inform [Leviathan X](https://leviathanx.org). Business contact: **admin@leviathanx.org**.

See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md) for the repository's existing terms and reporting guidance.
