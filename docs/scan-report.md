# Scan reports and coverage

[Home](../README.md) | [Scanning guide](scanning.md) | [CBOM output](output.md)

The CBOM describes the inventory. The optional scan report describes how
collection ran, including scope, diagnostics, preparation, and failures.

## Write a scan report

For detailed execution and reproducibility information, write a separate report:

```sh
./bin/ciphertrail scan . --output cbom.json --scan-report scan-report.json
```

`--scan-report` requires a file path; it does not replace the CBOM or use stdout.
It is optional and is independent of `--summary` and `--include-dependencies`.
Current output paths and recognized previous scan reports are excluded from
repository discovery.

Use `--scan-report` in pipelines when detailed audit/reproduction information
must accompany the CBOM. See [exit codes and output safety](output.md#exit-codes-and-output-safety)
for partial results, replacement restrictions, and atomic-write behavior.

## Report contents

The optional JSON artifact has `reportFormat: "CipherTrailScanReport"` and
`reportVersion: 1`. It contains scanner identity/time, output scope/status,
component statistics, and a `collections` array with per-input target, outcome,
errors, diagnostics, coverage, and structured `details`.

Directory-associated collections include a `project-subject` detail containing
the enclosing source-project `bom-ref`. This links overlapping input records and
shared Python analysis back to their project without repeating absolute input
targets in the CBOM header. Project context contributes to component statistics,
not cryptographic finding counts.

When a CBOM was generated, `bomLink` is a standard CycloneDX BOM-Link
(`urn:cdx:<uuid>/<version>`) identifying that exact document. It shares the CBOM's
generation timestamp and scanner identity. If CBOM encoding failed, no link is
invented. A generated-but-unwritten CBOM can still be linked while `outputError`
explicitly records the write failure.

Metadata values are supplied as typed values by collectors. Arrays and objects,
such as exclusions and Go build context, remain JSON arrays/objects; the report
does not guess structure from strings that happen to resemble JSON.
Component statistics distinguish collected, exported, omitted, and cryptographic
components. Collection and CBOM-output failures are recorded when a report path
was requested; a failed report write still returns an operational error.

## Coverage and diagnostics

Each report coverage record identifies its analyzer, status, inspected files/modules,
cryptographic finding count, skipped inputs, and any preparation reason.
Statuses distinguish `completed`, `failed`, `not-applicable`, `needs-rendering`,
and `deduplicated`. A file analyzer requiring rendered inputs reports
`needs-rendering` even if other files produced findings. Counts and detailed
diagnostics do not imply exhaustive cryptographic coverage. Source build-context
options require the `go` analyzer.

Stderr contains one coverage summary per input. Identical diagnostic messages
are grouped with an occurrence count; every original diagnostic location is
available in the scan report. Exclusions and recognized report files are listed
in its `scope` detail, not printed as hundreds of individual notes.
