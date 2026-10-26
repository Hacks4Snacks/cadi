# Development and extension

[Home](../README.md) | [Build and scan](scanning.md) | [Output contract](output.md)

## Build identity

Stamp an explicit scanner release version with:

```sh
make build VERSION=v0.1.0
```

This version is shared by the CLI, CBOM generator identity, and scan report. It
does not set the version of the project being scanned. Without a release
override, available module/VCS build information identifies development builds.

The module path is `ciphertrail` for local development. Publishing under a
repository namespace requires updating the module path and internal imports.

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
