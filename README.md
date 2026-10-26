# CipherTrail

Cryptography discovery, backed by evidence.

CipherTrail is a command-line tool that generates **CycloneDX 1.7 cryptographic
bills of materials (CBOMs)**. It identifies supported algorithms, protocols,
certificates, and keys, together with public parameters, dependency context, and
the evidence behind each finding.

## What it does

- **Analyze Go and Python source** for cryptographic API calls and configuration.
- **Inspect Kubernetes manifests and rendered Helm output**, including supported
  configuration embedded in ConfigMaps and bootstrap profiles.
- **Scan local files and container images** for public certificate/key metadata,
  supported configuration, and Go binary build information.
- **Probe explicitly selected TLS and SSH endpoints** for handshake or host-key
  evidence, without logging in or running remote commands.
- **Combine inputs into one CBOM**, with an optional terminal summary and a
  separate scan report for collection details. Directory scans use one enclosing
  project subject across their languages and file types.

Findings distinguish **configured**, **present**, and **observed** evidence.
Source configuration is not proof of runtime use, and successful collection does
not mean exhaustive discovery.

## Quick start

Build from this checkout with **Go 1.27+**. Python source analysis also requires
a trusted **Python 3.10+** interpreter on `PATH` as `python3`; no Python packages
are needed.

```sh
go mod download
make build
./bin/ciphertrail scan /path/to/repository \
  --output cbom.json \
  --scan-report scan-report.json \
  --summary
```

The command discovers applicable Go, Python, Kubernetes, and artifact inputs.
`cbom.json` contains the crypto-focused inventory; `scan-report.json` contains
coverage and diagnostics. The summary goes to stderr.

For analyzer selection, combined inputs, exclusions, and offline operation, start
with the [scanning guide](docs/scanning.md).

## Documentation

| Guide                                       | Covers                                                                            |
|---------------------------------------------|-----------------------------------------------------------------------------------|
| [Scanning](docs/scanning.md)                | Build, input selection, repository boundaries, exclusions, and offline scans      |
| [Go](docs/go.md) / [Python](docs/python.md) | Supported APIs, parameter resolution, dependencies, and analysis limits           |
| [Kubernetes and Helm](docs/kubernetes.md)   | Rendered manifests, ConfigMaps, bootstrap profiles, and source locations          |
| [Files and images](docs/artifacts.md)       | Supported material formats, image handling, and privacy boundaries                |
| [TLS and SSH probes](docs/runtime.md)       | Explicit endpoint scans, mTLS, trust, and observation limits                      |
| [CBOM output](docs/output.md)               | Evidence, native crypto fields, dependency context, exit codes, and output safety |
| [Scan reports](docs/scan-report.md)         | Structured execution metadata, diagnostics, and coverage                          |
| [Development](docs/development.md)          | Tests, build identity, package layout, and extending collectors                   |

## Boundaries

CipherTrail does not execute scanned application code, render charts, discover
network targets, or access clusters. It does not upload source to a hosted scanner
or include private-key values in reports. Reports can still contain sensitive
operational metadata and should be handled accordingly.

Go analysis may download missing dependencies through your existing Go settings.
Use `--offline` for cache-only scans. CipherTrail does not score risk, enforce
cryptographic policy, claim compliance, or remediate findings.
