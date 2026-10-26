# Scanning repositories and files

[Home](../README.md) | [CBOM output](output.md) | [Scan reports](scan-report.md)

Use this guide to build CipherTrail, select inputs, and control discovery scope.
Commands assume the current directory is the CipherTrail checkout; replace scan
paths with the repositories or files you want to inventory.

## Build and run

Building requires Go 1.27 or newer. Go analysis needs a compatible local `go`
executable. Python analysis needs a trusted Python 3.10+ interpreter available
as `python3`, only when selected Python source is present. No Python packages,
Docker daemon, database, hosted scanner, or cluster access are needed.

```sh
go mod download
make build
./bin/ciphertrail version
./bin/ciphertrail scan . --output cbom.json
```

See [development](development.md#build-identity) for release-version stamping.

## Inputs and analyzers

The canonical command is `ciphertrail scan PATH...`. Directories are mixed
repository roots; files are explicit passive inputs. Go, Python, Kubernetes,
and artifact analysis run where applicable and contribute to one CBOM.
Repositories without Go modules or Python source record `not-applicable` for
those analyzers rather than requiring their language tooling.

Each selected directory has a source-project identity independent of its
languages. A single logical root becomes the CBOM's primary subject; Go, Python,
manifest, and local-artifact findings share that project context. See
[document and primary-component identity](output.md#document-and-primary-component-identity)
for aggregation and stable-reference behavior.

Use `--analyzers` to restrict passive analysis:

```sh
./bin/ciphertrail scan . --output cbom.json
./bin/ciphertrail scan . --analyzers go,kubernetes --output cbom.json
./bin/ciphertrail scan . --analyzers python --output python.cbom.json
./bin/ciphertrail scan ./rendered.yaml --analyzers kubernetes --offline
```

The available analyzer names are `go`, `python`, `kubernetes`, and `artifact`.
Omitting `--analyzers` selects all four; an empty or unknown selection is an error.
Images and TLS/SSH targets remain explicit options, not inferred from references
found in a repository. Go analysis needs a directory with a `go.mod` at or below
that root; it does not treat an isolated `.go` file as a complete project.

| Input                | Evidence collected                                           | Important boundary                                        |
|----------------------|--------------------------------------------------------------|-----------------------------------------------------------|
| Go source            | Resolved crypto API calls, parameters, modules, dependencies | Configuration evidence, not proof of execution            |
| Python source        | Import-qualified crypto calls and bounded parameter facts    | Static AST analysis; no target imports or execution       |
| Local files          | Public material, Go binary metadata, supported configuration | No private-key values; no target program execution        |
| Local image          | Effective filesystem using the same file detectors           | Single-image Docker save TARs and OCI layout directories  |
| Kubernetes manifests | Certificate declarations, TLS Secret material, Ingress TLS   | Local YAML/JSON only; no Helm execution or cluster access |
| TLS target           | Negotiated version/cipher, peer certificate chain, ALPN      | One handshake, not exhaustive capability enumeration      |
| SSH target           | Public host key, key format, size/curve, fingerprint         | Stops before user authentication; no commands or login    |

Inputs can be repeated and combined in one report:

```sh
./bin/ciphertrail scan \
  ./service \
  ./certificates \
  ./service-binary \
  --image ./service-image.tar \
  ./rendered-manifests \
  --output service.cbom.json
```

Flags may appear before or after paths. Use `--` before a path beginning with `-`.
Go uses the host build platform unless you select another context:

```sh
./bin/ciphertrail scan . --goos linux --goarch amd64 --tags production
```

Without `--output`, JSON goes to stdout. Coverage summaries, grouped diagnostics,
and operational errors go to stderr. Overlapping paths are normalized and shared
file/module work is deduplicated without merging distinct evidence contexts.

Use [`--summary`](output.md#human-readable-summary) for a crypto-focused table on
stderr and [`--scan-report`](scan-report.md) for detailed execution metadata.
[`--include-dependencies`](output.md#crypto-focused-output) expands the exported
software inventory without changing collection.

## Repository boundaries

A directory root is scanned as one repository. Discovery stops at nested
directories containing a `.git` directory or file, including independent
checkouts, submodules, and worktrees. Ordinary nested Go modules without a Git
boundary are still scanned.

This avoids accidentally inventorying another checkout's examples, test modules,
and services just because it is stored beneath the selected repository. Skipped
roots are recorded in `ciphertrail:excluded-nested-repositories`; the effective
mode is recorded in `ciphertrail:nested-repository-scope` in the scan report.

To include another repository deliberately, add it as a source root or opt into
recursive repository discovery:

```sh
./bin/ciphertrail scan ./project ./project/other-repository
./bin/ciphertrail scan ./project --include-nested-repos
```

Explicit source exclusions still apply in recursive mode. Required imports are
still resolved and type-checked across repository boundaries; a boundary is not
a way to suppress missing dependencies or compilation failures in required code.
Normal dependency inventory includes the versions the target actually imports,
not every module in an unrelated checkout.

Ordinary overlapping directory inputs share their enclosing selected project.
An explicitly selected nested Git repository remains a separate project even
with `--include-nested-repos`; its files and modules are assigned to that input
instead of being collected again through the ancestor. Such transferred work is
recorded as `separate-project-root` omissions in the ancestor's scan-report scope.
This does not change exclusions at each explicitly selected root.

## Shared repository exclusions

Repository discovery excludes hidden metadata directories and common output,
dependency, and fixture directories: `vendor`, `node_modules`, `testdata`, `test`,
`tests`, `mocks`, `samples`, `examples`, `bin`, `out`, `dist`, `build`, `target`,
`coverage`, and `__pycache__`. The selected root itself is not excluded by its
name. Recognized CBOM/SBOM files and the requested output files are excluded so
generated inventories are not recursively scanned.

Child directories marked by `pyvenv.cfg` are omitted as Python virtual
environments, without reading their configuration or dependencies. An ordinary
directory named `env` is not excluded just because of its name.

Go also excludes `_test.go` files through its build context. A normal file such
as `internal/testutil/crypto.go` is still ordinary Go source; CipherTrail does not
guess that it is test-only from its directory name. See
[Go source scope](go.md#resolution-and-source-scope) for package-selection limits.

Python omits `test_*.py`, `*_test.py`, and `conftest.py` during automatic source
analysis. An explicitly supplied `.py` file can select a test module, subject to
the same hard exclusions as other inputs.

Add literal root-relative file or directory paths to `.ciphertrailignore` at
each selected directory root. These rules apply to every passive analyzer:

```text
# Test-only source maintained by this project
internal/testutil/
test/fixtures/
```

CipherTrail's own `.ciphertrailignore` excludes `internal/testutil/`, so a normal
self-scan omits its disposable certificate/key fixtures. This is separate from
`.gitignore`: helper code stays in version control and continues to run in tests.

For a one-off scan, use repeatable `--exclude` options:

```sh
./bin/ciphertrail scan . \
  --exclude internal/testutil \
  --exclude test/fixtures \
  --output cbom.json
```

File and CLI exclusions are combined, normalized, and recorded with omissions,
chart roots, and deduplication counts in the scan report's structured `scope`
detail. Paths are anchored to each directory root and match complete path
segments; `internal/testutil` does not exclude `internal/testutilities` or
`production/testutil`. Blank lines and lines beginning with `#` are ignored.
Glob patterns, negation, absolute paths, and parent traversal are rejected rather
than silently misinterpreted.

Only the `.ciphertrailignore` at each explicit directory root is read; parent and
nested ignore files are not inherited. Explicit files outside a selected directory
use their containing directory as the scope root. The ignore file must be regular,
not a symlink, and no larger than 64 KiB. `.gitignore` is not implicitly treated as
cryptographic scope.

Excluded packages and nested modules are removed from the scan roots.
Excluded files do not generate source findings or unmodeled-API notes, including
TLS configuration findings. This is an analysis-scope control, not a compilation
sandbox: files belonging to a retained package, and dependencies needed by
retained code, may still be read for Go type checking. Compilation errors in
required code remain errors.

Explicit file inputs can select material under default-excluded directories.
When a file lies within a selected repository, that repository's configured
exclusions still apply. Each explicitly selected directory has its own scope;
overlapping selections are combined before file/module work is assigned.
Repository exclusions do not filter separately supplied images or active probes.

## Offline and private-repository scans

Go scans prepare missing dependencies through the normal Go proxy and
authentication settings unless `--offline` is set. The target's manifests and
checksum files are not modified. Cache-only scans require the selected modules
and checksums to be available locally:

```sh
./bin/ciphertrail scan /path/to/repository --offline --output cbom.json
```

`--offline` cannot be combined with TLS/SSH probes. For private-module setup,
workspace handling, and package-load troubleshooting, see
[Go dependency preparation](go.md#dependency-preparation-and-read-only-analysis).
