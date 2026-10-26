# Understanding CBOM output

[Home](../README.md) | [Scanning guide](scanning.md) | [Scan reports](scan-report.md)

CipherTrail produces CycloneDX 1.7 JSON. This guide covers:

- [Crypto-focused output](#crypto-focused-output) and dependency context.
- [The human-readable summary](#human-readable-summary).
- [Evidence and provenance](#evidence-and-provenance).
- [Native algorithm facts](#native-algorithm-facts).
- [Native material formats](#native-material-formats).
- [Document identity](#document-and-primary-component-identity).
- [Exit codes and safe output files](#exit-codes-and-output-safety).

## Crypto-focused output

By default, the CBOM contains:

- Cryptographic assets and their evidence.
- Ownership context, including enclosing applications, container images, and
  Kubernetes configuration resources.
- Identified input subjects, including directory-project scope, even when they
  contain no cryptographic findings.
- Explicit implementation dependencies and native cryptographic reference
  targets needed to explain those findings.

Ordinary software imports do not establish cryptographic relevance. Unrelated
libraries are removed together with their dependency edges; importing a retained
crypto provider does not automatically retain every other consumer of that
provider.

For Go source findings, CipherTrail links the crypto use to the resolved module
providing the called API, or to the versioned Go standard library. This is
source-level implementation context, not proof of runtime execution. Runtime
probes do not infer the remote server's implementation library.

Python provider libraries use concise labels such as `requests`, retaining their
source-import/API qualification in `ciphertrail:scope`. No installed distribution,
version, or TLS backend is inferred from that label. The protocol/algorithm and
the supporting library remain separate components connected by `dependsOn`;
both can legitimately cite the same call site. In the optional summary, that
appears as one crypto finding with `requests` in the API/library column, not as
two crypto findings. API/library context is not necessarily the cryptographic
implementation.

To include the full collected software/dependency inventory instead:

```sh
./bin/ciphertrail scan . --include-dependencies --output combined-bom.json
./bin/ciphertrail scan ./service-binary --include-dependencies --output binary-bom.json
```

Both modes use the same collectors and preserve crypto asset references,
evidence, errors, and uncertainty. Only the exported component/relationship
scope changes. A default scan with no discovered cryptographic assets can
have an empty `components` array while still identifying its primary subject in
`metadata.component`; that subject is not a crypto finding. Concise
execution/coverage qualifications remain in the header, with detailed context
available in the optional scan report and CLI diagnostics.
Go binary build information alone establishes dependency presence, not
cryptographic use, so use `--include-dependencies` to export that inventory.
Neither omitted software nor an empty crypto inventory proves absence of
cryptography.

## Human-readable summary

For a crypto-focused view alongside the complete JSON report:

```sh
./bin/ciphertrail scan . --summary --output cbom.json
```

`--summary` adds a table on stderr with one row per cryptographic asset, its
evidence kind and source locations, and directly linked API/library names.
Supporting libraries and applications are not additional finding rows or part of
the crypto count. The table remains crypto-focused with `--include-dependencies`;
that option still controls the JSON inventory. Partial collections are labeled
`INCOMPLETE`, and an empty summary does not establish absence of cryptography.
Control characters in table cells are escaped.

## Evidence and provenance

Every generated CBOM is validated against bundled CycloneDX 1.7 JSON Schemas,
without network access. Standard `cryptoProperties`, software dependencies, and
evidence occurrences carry the inventory. Each native occurrence has a stable,
BOM-wide unique `bom-ref`; its location, line, and symbol are recorded only there.
Evidence distinguishes configured intent, material present in an artifact, and
runtime observations.

Per-component namespaced properties add:

- `ciphertrail:evidence-kind` and `ciphertrail:collector`: flat classification
  and collector fields when every evidence record for a component is simple
  and agrees on both values. These apply to all of its native occurrences.
- `ciphertrail:provenance`: occurrence-linked records when evidence has differing
  classifications/collectors or additional detail: observation time, a
  location-free symbol, source-locator context, or declaration facts. These retain
  `present` / `configured` / `observed` classification and collector. Qualified
  parameter facts are grouped by shared `basis` and `limitation`; each group's
  `values` retain their names, values, and definition locations. Definition
  locations describe parameter origins, not duplicate copies of the asset's use
  site. Structured inputs also carry optional document/field/embedded-file `context`.
- Resolved public parameters and qualified `:declared` alternatives. Missing
  parameters are not replaced with invented values or defaults.

Collectors emit facts directly into their native fields: Go API identity is
already in `evidence.occurrences.symbol`, and a mapped algorithm key-size value
is written to `cryptoProperties.algorithmProperties.parameterSetIdentifier`
without also emitting `ciphertrail:key-size-bits`. Parameters with no native
mapping, including qualified declarations, remain properties.

The exporter does not parse source-symbol strings or match algorithm-name
patterns to decide which properties to remove. It preserves properties supplied
by collectors and selects the provenance shape from typed evidence records.
Both dependency-output modes follow the same rules. Removing redundant facts
at collection time can change component and occurrence references because
identity includes collected metadata; regenerated references and graph links
remain deterministic and internally consistent.

Unresolved lists are omitted through a typed evidence projection, including
nested source contexts. Internal uncertainty still prevents guessed values, and
operational failures, coverage gaps, and unmodeled-API diagnostics remain visible.
An absent field means it was not reported, not that it is known, false, or safe.

Detailed supplemental provenance is associated with its own occurrence, so
declarations and observations from different locations remain distinct.
Evidence without a location remains component-scoped; no occurrence is invented,
and a symbol is retained in supplemental provenance if one was supplied.
Repeated generic source-analysis caveats belong in versioned documentation.

### Reading component properties

For simple source evidence, the component properties are:

```json
[
  { "name": "ciphertrail:collector", "value": "go" },
  { "name": "ciphertrail:evidence-kind", "value": "configured" }
]
```

For richer evidence, a decoded `ciphertrail:provenance` property can contain:

```json
{
  "occurrence": "urn:ciphertrail:<occurrence-hash>",
  "kind": "configured",
  "collector": "go",
  "parameters": [
    {
      "basis": "declared-policy-initializer",
      "limitation": "declared configuration only; exported mutable policy may change before use",
      "values": [
        {
          "name": "cert-manager.key-size",
          "value": "2048",
          "location": "pkg/certpolicy/client.go",
          "line": 40
        }
      ]
    }
  ]
}
```

Consumers should read the flat classification for simple components. For detailed
records, join `provenance.occurrence` to `evidence.occurrences[].bom-ref` and read
grouped `parameters[].values`. Do not infer values from omitted fields or treat
a literal string `"unknown"` as a placeholder. The optional `--summary` understands
both forms. Existing reports can be replaced by rescanning.

## Native algorithm facts

Recognized API and material models emit known facts directly into CycloneDX 1.7
`cryptoProperties.algorithmProperties`, rather than reconstructing them from
display names during export:

- `algorithmFamily` uses the schema's registered family identifiers. A generic
  RSA key does not establish RSAES-OAEP, RSAES-PKCS1, RSASSA-PKCS1, or RSASSA-PSS;
  those families require an explicit operation or signature scheme. Families
  absent from the schema, including scrypt and Argon2, are not invented.
- `parameterSetIdentifier` is algorithm-specific: SHA-256 records digest length
  `256`, SHAKE128 records its `128` parameter rather than its requested output
  length, and a known RSA or AES key length remains a key-size parameter.
  HMAC's digest selection does not establish its key length. Variable BLAKE2
  output lengths are recorded when explicit, without assuming library defaults.
- `cryptoFunctions` records modeled cryptographic purpose, including digest,
  tag, key generation/derivation, signing/verification, encryption/decryption,
  random generation, and KEM encapsulation/decapsulation. This is not proof of
  execution. Public-key presence and generic cipher constructors do not invent
  an encrypt/decrypt/sign operation.

Known OIDs are emitted in `cryptoProperties.oid`. The bounded mappings cover
fixed hashes, supported SHA-2/SHA-3 HMAC identities, resolved AES mode/key-size
combinations, explicit RSA-OAEP/PSS schemes, Ed25519/Ed448 and X25519/X448
identities, ML-KEM and ML-DSA parameter sets, and recognized X.509 signature algorithms.
Mappings follow the [NIST CSOR](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration),
[RFC 4231](https://www.rfc-editor.org/rfc/rfc4231),
[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017), and
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410).
An OID is an algorithm identifier, not evidence that unresolved parameters or an
operation are valid. Generic algorithms, unknown keys/modes, unsupported OID
variants, and opaque signature options remain unqualified.

Formats such as PKCS#10 do not by themselves establish a signing algorithm.
No execution backend, certification, classical security strength, or
post-quantum security level is inferred by this enrichment.

These native fields are the same in crypto-focused and full-dependency output.
Rescan to enrich an existing CBOM. References derived from component metadata can
change when facts are added; consolidation rules and reference consistency are
preserved.

## Native material formats

Known source and material representations are recorded in
`cryptoProperties.relatedCryptoMaterialProperties.format`:

| Format    | Evidence                                                                                                                                            |
|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `DER`     | Go PKCS#1, PKCS#8, PKIX/SPKI, SEC1 and PKCS#10 parse/serialization APIs; Python DER key/CSR loaders; parsed DER keys and certificate-embedded SPKI  |
| `PEM`     | Go SSH private-key parsers; Python PEM key/CSR loaders and PEM-armored OpenSSH private-key loading; parsed PEM keys, including encrypted containers |
| `OpenSSH` | OpenSSH authorized-key text parsed or produced by supported Go/Python APIs or read from a file                                                      |
| `SSH`     | Binary SSH public-key wire encoding, including `ssh.PublicKey.Marshal`, `ssh.ParsePublicKey`, and observed SSH host keys                            |

Encoding is not an algorithm or a container type: PKCS#1/PKCS#8/PKCS#10 identity
remains in API symbols, names, or explicit configuration properties. For
cert-manager, explicit supported `PKCS1` and `PKCS8` declarations both specify a
PEM envelope; their original `cert-manager.key-encoding` values are retained.
Missing, dynamic, unsupported, and qualified-only declarations do not establish
an unconditional format at their use site.

Python CSR imports and CSR signing declarations use `related-crypto-material`
with type `other`, matching Go CSR models rather than representing an issued
certificate. Import APIs establish PEM/DER; a signing call returning an in-memory
CSR does not establish serialization. Public-key access, validation, and other
in-memory key operations likewise do not invent an encoding.

Formats describe configured API contracts or observed representations, not
successful parsing, issuance, decryption, or private-key contents. Parsed
certificates still use `certificateProperties.certificateFormat: "X.509"`; the
format of their embedded public key is DER, not the outer certificate's envelope.

One mathematical key may occur in several encodings. Its stable key reference
and consolidation are preserved. If every collected observation agrees, the
format is emitted once in the native field. If formats differ, or some
observations have no established format, the native field is omitted and known
values are retained as occurrence-linked `materialFormat` fields in
`ciphertrail:provenance`. Input order does not select a winning format.

Both output scopes use the same rules. Rescan existing CBOMs to populate the
new fields; configured-component references can change when collected metadata
is enriched.

### Native material relationships

The complete schema bundle, including `cryptography-defs.schema.json`, is pinned
to the official 1.7 release. Generation and validation target 1.7 only.
There is no version-conversion step that might discard or change assets.

The 1.7 output uses native `certificateProperties.serialNumber` instead of the
former `ciphertrail:certificate-serial-number` property. Curves use
`algorithmProperties.ellipticCurve` with canonical identifiers such as
`nist/P-256`, `other/Ed25519`, and `other/Curve25519`. Certificates, keys, and
protocols use `relatedCryptographicAssets` for their relationships, with explicit
roles (`publicKey`, `signatureAlgorithm`, `algorithm`, and `certificate`).
All these references participate in graph validation and crypto-focused pruning.
Certificate component hashes remain SHA-256 over the full DER certificate;
private-key material and private-key digests are not exported.

## Header metadata

The CBOM header retains native generation time and scanner identity, plus only:

- `ciphertrail:collection-status`: `succeeded` or `incomplete` execution.
- `ciphertrail:output-scope`: `crypto-focused` or `full-dependencies`.
- `ciphertrail:coverage-limitation`, when needed: concise qualifications such as
  rendering required, failed analysis, or analysis diagnostics being reported.

It does not contain serialized collection payloads, omission counters, input-target
lists, build-context dumps, diagnostic lists, or generic scope prose. A primary
component's native identity and evidence can include its own path or endpoint.
Successful execution is not a claim of exhaustive coverage or secure cryptography.
Both inventory modes use this same compact metadata contract.

Scanner identity uses an explicit release version when supplied. Otherwise,
available Go module/VCS build information supplies the version, including a
revision and dirty-worktree marker for development builds. `dev` is used only
when no more precise identity is available. CLI `version`, CBOM, and scan report
use the same identity; parser/compiler versions are not target-runtime claims.

## Document and primary-component identity

Each generated CBOM has a fresh UUIDv4 `serialNumber` (`urn:uuid:...`) and document
`version: 1`. Rescanning or changing output scope creates a new document, including
for empty or incomplete inventories. Document identity is independent of stable
component and occurrence references; it is not a content hash or the scanner's
release version.

For a directory input, scan orchestration creates one **source-project subject**
for its selected root. Go modules, Python source, configuration resources, and
local material are inventoried beneath that same project. Enabling an additional
analyzer does not remove or change the primary project identity.

The source-project component uses:

- `type: "application"` to represent the logical source-project scope, not an
  assertion that a running or deployable application was observed.
- The selected root directory's basename as its display name.
- A deterministic `bom-ref` derived from the normalized absolute directory path,
  independent of analyzer selection, findings, and output scope. Moving the
  checkout changes this local scope identity; it is not a global repository ID.
- A description identifying it as source-project inventory and a native `.`
  occurrence denoting the selected root. Physical targets remain available in
  the scan report.
- No inferred project version, package URL, deployment state, or scanner version.

When inputs agree on one subject, it appears in `metadata.component` and is not
duplicated in `components`. Existing Go/Python components remain distinct beneath
the project, using their original identities, facts, and evidence. Project
ownership is added after collection without regenerating cryptographic asset
references. Ordinary dependencies retain their dependency semantics; an imported
library is not relabeled as project-owned source.

| Selection | Subject behavior |
|---|---|
| One directory, with any analyzer combination | One source-project subject |
| One directory containing several Go modules or a workspace | One enclosing project; relevant module contexts remain distinct |
| A directory plus ordinary overlapping subdirectories/files | One project; shared work is deduplicated |
| Explicitly selected independent repositories, including nested Git checkouts | Separate project components; no arbitrary primary subject |
| A subdirectory without its enclosing repository root | A subject for the selected subtree, not the whole repository |
| Explicit Go binary, single image, TLS/SSH endpoint, or standalone Python source | Existing collector-identified subject behavior |
| Standalone material/configuration file | No fabricated project/application subject |

A single selected root with `--include-nested-repos` still describes that selected
scope. Explicitly selecting a nested independent repository keeps its project
separate, including in recursive mode. A monorepo subject describes an enclosing
inventory, not a claim that all its applications are one deployed application.

Identified subjects remain visible in crypto-focused output even for empty or
incomplete scans. Multiple distinct subjects remain in `components` rather than
being promoted. Unknown additional inputs still prevent selection of an
unambiguous primary subject. Coverage limits, collection errors, and excluded
files are not hidden by project context.

Compared with earlier output, a directory's Go module or Python component is no
longer promoted by itself: the new enclosing project occupies `metadata.component`.
This adds project context to total component counts without increasing
cryptographic-finding counts or changing existing asset consolidation.

Consumers must include `metadata.component` when indexing components or resolving
dependency references. `--summary` and scan-report statistics account for it
without treating a software subject as a cryptographic finding.

Stable component references and sorted relationships make reports comparable.
Document UUIDs and observation/report timestamps vary between runs. Collection
success does not mean exhaustive discovery or a secure configuration.

## Exit codes and output safety

| Exit | Meaning                                                            |
|------|--------------------------------------------------------------------|
| 0    | Collectors succeeded; declared limitations and unknowns may remain |
| 1    | Collection, schema validation, or output failed                    |
| 2    | Invalid command, flags, input combination, or endpoint syntax      |

When one collector fails, successfully collected evidence is retained in a
schema-valid partial report and the command exits 1. No algorithm choice,
certificate expiry, or key size causes a policy exit.

Named CBOM and scan-report output files are written atomically with owner-only
permissions. CipherTrail refuses to overwrite explicit inputs, credentials,
symlinks, special files, the other output, or unrelated existing files. Each
output can replace only a previous CipherTrail artifact of the same format,
provided that file did not change during collection. The two writes are
individually atomic, not a multi-file transaction; failure of either returns
exit 1.
Shell redirection is outside these protections: never redirect stdout onto an
input file.
