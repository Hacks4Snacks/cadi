# Development and extension

[Home](../README.md) | [Build and scan](scanning.md) | [Output contract](output.md)

## Transition from CipherTrail

The project is now **Cryptographic Asset Discovery and Inventory (CADI)**.
The executable and local Go module are named `cadi`.

| Surface | Previous name | Current name |
|---|---|---|
| Command / build output | `ciphertrail` / `bin/ciphertrail` | `cadi` / `bin/cadi` |
| Entry point / local module | `cmd/ciphertrail` / `ciphertrail` | `cmd/cadi` / `cadi` |
| Repository exclusions | `.ciphertrailignore` | `.cadiignore` |
| CBOM/report generator | `ciphertrail` | `cadi` |
| Custom properties | `ciphertrail:*` | `cadi:*` |
| Component and occurrence references | `urn:ciphertrail:*` | `urn:cadi:*` |
| Execution report format | `CipherTrailScanReport` | `CADIScanReport` |

All newly generated output uses CADI identifiers. CycloneDX remains version 1.7,
execution reports retain `reportVersion: 1`, and document UUIDs/BOM-Links keep
their standard formats. Changing the reference namespace and property names
changes generated component/occurrence IDs; consumers must not assume ID equality
across the rename. Asset consolidation, evidence semantics, and scanner limits
are unchanged.

For migration, `.ciphertrailignore` remains supported. When both ignore files
exist, their rules and CLI exclusions are combined, not overridden. Both files
retain the same validation and output-overwrite protection. Rename your existing
ignore file to `.cadiignore` when convenient.

Previously generated CipherTrail CBOMs and scan reports remain recognizable for
discovery exclusions and safe replacement of explicitly selected output files.
They are not rewritten merely by scanning their directory. Unknown generators,
unrelated files, symlinks, and input/output collisions remain protected.

Update scripts to invoke `cadi`; there is no new `ciphertrail` command alias.
Release archives use names such as `cadi_v0.1.0_linux_amd64.tar.gz`, containing
`cadi` (`cadi.exe` on Windows). The checkout directory can keep its existing name.
Repository hosting, remotes, existing generated reports, and installed old
binaries are not renamed automatically.

## Build identity

Stamp an explicit scanner release version with:

```sh
make build VERSION=v0.1.0
```

This version is shared by the CLI, CBOM generator identity, and scan report. It
does not set the version of the project being scanned. Without a release
override, available module/VCS build information identifies development builds.

The module path is `cadi` for local development. Publishing an installable
Go module under a repository namespace requires updating the module path and
internal imports. GitHub binary releases do not require that change.

## Checks

```sh
make test
make check
make build
```

Tests cover graph pruning/reference closure, optional full inventory,
source symbols/parameters, offline workspaces, nested modules,
TLS/mTLS, SSH pre-authentication termination, timeouts, asset privacy, image
whiteouts/traversal, multi-document Kubernetes manifests, embedded Secret
privacy, detector registration, input parity, output safeguards, and official
schema validation. A bounded manifest fuzz target also checks that malformed
inputs retain schema-valid partial inventories.

## Release automation

The [release workflow](../.github/workflows/release-please.yml) runs on branch
pushes and calls [CI](../.github/workflows/ci.yml). CI also runs on pull requests
and can be dispatched manually. It verifies dependencies, runs `make check`,
and checks version stamping. The Linux/Python 3.10 job also builds and checksums
all six release archives. Linux tests cover Python 3.10 and 3.15; macOS tests
cover Python 3.15. The Go version comes from `go.mod`.
Action revisions are pinned and [Dependabot](../.github/dependabot.yml) checks
for Action updates weekly.

Only pushes to the repository's configured default branch manage releases.
The branch name and repository owner are not hard-coded.

### Before enabling publication

1. Create/connect the GitHub repository and choose its default branch. This
   checkout initially has no remote; no hosted settings are changed by these
   files.
2. Choose and add a project `LICENSE` before public distribution. The existing
   CycloneDX schema license applies to those upstream files, not to CADI
   as a whole. Review dependency license/notice obligations and ensure generated
   scan reports and local operational data are not accidentally committed.
3. Enable Actions and **Settings > Actions > General > Allow GitHub Actions to
   create and approve pull requests**, subject to organization policy.
4. Recommended: add a repository secret named `RELEASE_PLEASE_TOKEN` containing
   a fine-grained PAT limited to this repository, with **Contents**, **Issues**,
   and **Pull requests** read/write permissions. A suitable GitHub App
   installation token can also be supplied, but must be refreshed by your own
   token-minting automation rather than stored as a long-lived secret.
5. Enable squash merging and use Conventional Commit PR titles. Require the CI
   `Go checks` matrix checks in branch protection or a ruleset before merging.
   These workflows do not enable auto-merge or bypass reviews.

Without `RELEASE_PLEASE_TOKEN`, release-please uses `GITHUB_TOKEN`. That can
create release PRs and releases, but its PR events do not trigger CI. If required
checks are enabled, manually run the **CI** workflow against the release PR
branch, or configure the dedicated token. Asset publication runs in the same
workflow as release-please, so it does not depend on a token-generated tag or
release event triggering another workflow.

### Versioning and normal releases

[Configuration](../release-please-config.json) selects a single root Go release,
`v`-prefixed tags, and an initial version of **0.1.0**. The
[manifest](../.release-please-manifest.json) starts at `0.0.0` to represent an
unreleased repository. After bootstrap, let release-please update it rather than
editing versions or creating release tags manually.

Use release-worthy Conventional Commits, for example:

```text
feat(scan): add a supported collector
fix(python): resolve an aliased cryptographic import
feat!: change the CBOM output contract
```

Features bump the minor version, fixes bump the patch version, and breaking
changes bump the minor version while below 1.0.0. At 1.0.0 and above, breaking
changes bump the major version. Existing non-conventional history does not
produce release notes; use a commit such as `feat: prepare initial release` to
start the first release PR.

1. Merge normal changes into the default branch. After CI passes, release-please
   opens or updates a release PR containing the changelog and manifest version.
2. Review and merge that PR. Release-please creates a tag and a **draft** GitHub
   release; forcing tag creation makes the draft's source available for checkout.
3. The publication job checks out that exact tag, reruns vet/race tests with
   Python 3.10, and builds CGO-disabled binaries for Linux, macOS, and Windows
   on amd64 and arm64. Linux/macOS use `.tar.gz`; Windows uses `.zip`.
4. It verifies archive checksums and the Linux binary's version, uploads the six
   archives and `SHA256SUMS`, then publishes the draft. Users do not see a
   published release before the assets are ready.

Each archive contains the executable, README, documentation, and CycloneDX
schema license/notice under `third_party/cyclonedx/`. A root project `LICENSE`
and `NOTICE` are included when present. Only the Linux binary is smoke-tested
during publication; Windows binaries are cross-compiled, not executed in CI.

### Local packaging and recovery

Packaging requires Go, `make`, `tar`, `zip`, and `shasum` on a POSIX host:

```sh
make check
make release VERSION=v0.1.0
(cd dist && shasum -a 256 -c SHA256SUMS)
```

The default output is the ignored `dist/` directory. Override `DIST_DIR` to build
elsewhere. `make release` requires a stable `vMAJOR.MINOR.PATCH` tag; it does not
create tags, call GitHub, or publish anything. The existing `make build` remains
a single development build, with an optional `BINARY` output-path override.

If publication fails, the release stays a draft. In **Actions > Release > Run
workflow**, select the default branch and enter the existing draft tag, such as
`v0.1.0`, in `tag`. This checks the tag against its manifest, reruns validation,
rebuilds/replaces draft assets, and publishes only after success. It refuses to
modify an already published release. With `tag` empty, a manual run performs the
normal CI and release-please flow.

Recovery tags must be reachable from the default branch's history; arbitrary
tags on unmerged branches cannot be used to publish.

## Package layout

The project remains one Go module and executable. Input acquisition, file
detection, project analysis, active interrogation, orchestration, and export are
separate boundaries:

- [`internal/input`](../internal/input): read-only local traversal and effective
  image streams, file lifetimes, bounded buffering, and optional random access.
- [`internal/scope`](../internal/scope): shared discovery snapshots, literal
  exclusions, repository boundaries, generated-report filtering, and Helm scope.
- [`internal/detect`](../internal/detect): the file-detector contract and dispatch.
- [`internal/detect/artifact`](../internal/detect/artifact): material, OpenSSL, and
  Go binary recognition independent of the input provider.
- [`internal/detect/kubernetes`](../internal/detect/kubernetes): typed local
  configuration detection; no Kubernetes client or Helm runtime.
- [`internal/goscan`](../internal/goscan): project-wide Go loading, SSA, and value
  analysis, kept separate from single-file detectors.
- [`internal/pyscan`](../internal/pyscan): isolated Python AST facts, import/binding
  resolution, Go-owned crypto models, and source coverage.
- [`internal/material`](../internal/material): shared public certificate/key
  metadata parsing, reused by file, manifest, image, and runtime collection.
- [`internal/probe`](../internal/probe): explicitly authorized TLS/SSH interrogation.
- [`internal/scan`](../internal/scan): validated requests, built-in composition,
  normalized/deduplicated planning, execution, cancellation, coverage, and
  structured execution reports; owns directory-project identity and attaches
  collector contexts without regenerating their component references.
- [`internal/inventory`](../internal/inventory): evidence, ownership, relationships,
  stable references, and reusable configuration constructors.
- [`internal/export/cyclonedx`](../internal/export/cyclonedx): graph selection,
  occurrence/provenance serialization, and offline schema validation.
- [`internal/cli`](../internal/cli): flags, presentation, exit codes, protected output.

## Add a file detector

1. Implement `detect.Detector` (`Name`, `Match`, and `Detect`) in a detector
   package. `Match` reports applicability or a preparation reason; `Detect`
   returns `inventory.Result` and whether the format was recognized.
2. Read through `input.File`; set an appropriate bound with `ReadAll`. Multiple
   detectors share the same buffered content. Do not retain readers after the
   callback or mutate shared buffers.
3. Register it in the scan composition layer. Local and image providers require
   no detector-specific edits.
4. Test the same detector on a directory and image, with source provenance,
   partial failures, secret sentinels, and validated graph relationships.

## Add an analyzer or probe

Project analyzers and active probes implement `inventory.Collector` directly.
Python analysis consumes the shared source selection and retains import/mutation
context without being an image file detector. New language analyzers can use the
same collector and evidence contracts. Live Kubernetes acquisition is not
implemented and would be an explicit new capability, not an implicit side effect
of manifest scanning.

The result contract retains typed CycloneDX components. New configuration
detectors use inventory constructors rather than manipulating export schemas;
this avoids inventing a second complete schema model or dynamic plugin system.
No detector mutates the final BOM.

`Entry.Parent` denotes ownership; `Result.DependOn` records ordinary dependencies.
Dependencies from cryptographic assets identify required implementation context.
Collector properties and diagnostics survive output pruning.

The bundled schemas retain their upstream license and attribution in
[`internal/export/cyclonedx/schema`](../internal/export/cyclonedx/schema).
