# CipherTrail

Cryptography discovery, backed by evidence.

CipherTrail is a Go-first CLI that generates CycloneDX 1.7 cryptographic bills of
materials (CBOMs) from source code, local artifacts, and explicit runtime
endpoints. It does not score risk, enforce cryptographic policy, claim
compliance, or remediate findings.

## Build and run

Requires Go 1.27 or newer. The source analyzer also needs a compatible local
`go` executable. No Docker daemon, database, hosted scanner, or cluster access
is needed.

```sh
go mod download
make build
./bin/ciphertrail version
./bin/ciphertrail scan --source . --output cbom.json
```

The module path is `ciphertrail` for local development. Publishing under a
repository namespace requires updating the module path and internal imports.

## Collectors

| Input       | Evidence collected                                          | Important boundary                                      |
|-------------|-------------------------------------------------------------|---------------------------------------------------------|
| Go source   | Resolved crypto API calls, parameters, modules, dependencies  | Configuration evidence, not proof of execution          |
| Local files | Public certificate/key metadata and Go binary build metadata | No private-key values; no target program execution      |
| Local image | Effective filesystem, crypto files, Go binaries, TLS config  | Single-image Docker save TARs and OCI layout directories |
| TLS target  | Negotiated version/cipher, peer certificate chain, ALPN      | One handshake, not exhaustive capability enumeration    |
| SSH target  | Public host key, key format, size/curve, fingerprint         | Stops before user authentication; no commands or login   |

Inputs can be repeated and combined in one report:

```sh
./bin/ciphertrail scan \
  --source ./service \
  --file ./certificates \
  --file ./service-binary \
  --image ./service-image.tar \
  --output service.cbom.json
```

An optional positional directory is equivalent to `--source`. Put flags before it:

```sh
./bin/ciphertrail scan --goos linux --goarch amd64 --tags production .
```

Without `--output`, JSON goes to stdout. Diagnostics go to stderr.

## Crypto-focused output

By default, the report contains:

- Cryptographic assets and their evidence.
- Software components that own those assets, including enclosing applications
  or container images.
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

To include the full collected software/dependency inventory instead:

```sh
./bin/ciphertrail scan --source . --include-dependencies --output combined-bom.json
./bin/ciphertrail scan --file ./service-binary --include-dependencies --output binary-bom.json
```

Both modes use the same collectors and preserve crypto asset references,
evidence, errors, and uncertainty. Only the exported component/relationship
scope changes. A default scan with no discovered cryptographic assets can
contain no components; its collection context and diagnostics remain in
metadata. Go binary build information alone establishes dependency presence,
not cryptographic use, so use `--include-dependencies` to export that inventory.
Neither omitted software nor an empty crypto inventory proves absence of
cryptography.

## Go analysis

The analyzer discovers nested modules, loads the selected build context using
Go's type checker, and uses SSA to identify actual cryptographic symbols.
Aliases do not defeat recognition, and unrelated functions with similar names
are not treated as cryptography.

### Repository boundaries

A source root is scanned as one repository. Discovery stops at nested
directories containing a `.git` directory or file, including independent
checkouts, submodules, and worktrees. Ordinary nested Go modules without a Git
boundary are still scanned.

This avoids accidentally inventorying another checkout's examples, test modules,
and services just because it is stored beneath the selected repository. Skipped
roots are recorded in `ciphertrail:excluded-nested-repositories`; the effective
mode is recorded in `ciphertrail:nested-repository-scope`.

To include another repository deliberately, add it as a source root or opt into
recursive repository discovery:

```sh
./bin/ciphertrail scan --source ./project --source ./project/other-repository
./bin/ciphertrail scan --source ./project --include-nested-repos
```

Explicit source exclusions still apply in recursive mode. Required imports are
still resolved and type-checked across repository boundaries; a boundary is not
a way to suppress missing dependencies or compilation failures in required code.
Normal dependency inventory includes the versions the target actually imports,
not every module in an unrelated checkout.

### Cryptographic API models

Recognizers cover common constructors and operations in these API families:

- RSA, AES, DES/3DES, ECDSA, Ed25519, ECDH/X25519, and ML-KEM.
- MD5, SHA-1, SHA-2, SHA-3, SHAKE constructors, and fixed-size BLAKE2 operations.
- HMAC, HKDF, PBKDF2, bcrypt, scrypt, and Argon2.
- ChaCha20, ChaCha20-Poly1305, and XChaCha20-Poly1305.
- Block-cipher mode constructors, including CBC, CTR, and GCM.
- X.509 certificate/key operations, certificate requests, TLS entry points,
  TLS configuration initializers, and SSH key/connection APIs.
- Elliptic-curve selection, public-key access, X.509 certificate-pool imports,
  explicit TLS handshakes, and SHA-256 SSH public-key fingerprinting.

This is a recognizer list, not a claim that every method in those packages is
modeled. Unmodeled calls in cryptographic packages still produce diagnostics,
including the source file and line. Metadata and lifecycle helpers are classified
by exact package, receiver type, and method name; they are not coverage gaps and
do not create fictitious cryptographic assets.

| APIs                                                    | Inventory treatment                                                |
|---------------------------------------------------------|--------------------------------------------------------------------|
| `elliptic.P224/P256/P384/P521`                            | Selected curve; no inferred signing or key-agreement use            |
| `crypto.Signer.Public`, `crypto.Decrypter.Public`         | Public-key access; runtime algorithm and key size remain unknown    |
| `ecdh.PrivateKey.PublicKey`, `ssh.CryptoPublicKey` method | Public-key access; no fabricated key bytes or size                  |
| `ssh.FingerprintSHA256`                                  | SHA-256 digest for fingerprinting, not an SSH signature algorithm    |
| `ssh.MarshalAuthorizedKey`                               | Public-key serialization; no key material exported                  |
| `rsa.PrivateKey.Validate`                                | Structural private-key check; no validity or compliance verdict     |
| `x509.CertificateRequest.CheckSignature`                 | CSR self-signature verification; no assumed algorithm or outcome    |
| `x509.Certificate.Equal`                                 | Certificate identity comparison; no new asset                       |
| `x509.CertPool.AppendCertsFromPEM`                        | Certificate import; actual certificates and trust remain unknown    |
| `tls.Conn.Handshake`, `HandshakeContext`                 | Configured TLS handshake, not observed protocol/cipher negotiation   |
| `elliptic.Curve.Params`, `CurveParams.Params`             | Metadata access; no new asset                                      |
| `ecdh.PublicKey.Curve`, `ssh.PublicKey.Type`              | Metadata access; no new asset                                      |
| `x509.SignatureAlgorithm.String`, `pkix.Name.String`      | Formatting only; no new asset                                      |
| `tls.ClientAuthType.String`, `tls.CipherSuiteName`        | Formatting only; no new asset                                      |
| `tls.Conn.ConnectionState`                              | State access; no runtime observation made by the source scanner     |
| `x509.NewCertPool`, `x509.CertPool.Clone`                 | Empty-container allocation or copy; no new certificate discovered   |
| `ssh.Conn.Close`                                        | Connection cleanup; no new asset                                   |
| `ssh.Channel.Read/Write`, `ssh.Client.NewSession`         | Configured SSH protocol use; negotiated algorithms remain unknown  |
| `ssh.Session.Shell`                                     | Configured SSH shell request; no remote execution by the scanner     |
| `ssh.PublicKeys`                                        | Public-key authentication configuration; signer details unknown     |
| `ssh.InsecureIgnoreHostKey`                              | Host-key-check callback configuration, not a policy verdict         |
| `ssh.Channel.Close`, `ssh.Session.Wait`                  | Channel cleanup and command-wait lifecycle; no new asset             |
| `ssh.Session.StdinPipe/StdoutPipe/StderrPipe`             | Stream accessors; no new asset                                     |
| `rsa.PublicKey.Equal`                                   | Public-key identity comparison; no new asset                        |

The static-analysis scope reminder is retained in the CBOM as
`ciphertrail:analysis-scope` in collection properties and on retained scanned Go
modules, rather than printed on every successful scan. Unknown parameters remain
explicit in per-occurrence `unresolved` summaries, not value-shaped placeholders.
There is no
blanket suppression for methods named `String`, `Close`, `Public`, or `Verify`.

Parameter resolution includes integer constants, supported arithmetic, fixed
byte-array/slice lengths, equal-valued branches, and bounded propagation through
unexported non-escaping local functions. Exported parameters, ambiguous callers,
opaque interfaces, unsupported flows, and dynamic values remain unknown.
For RSA generation through receiver fields, explicit integer field initializers
are recorded as qualified alternatives rather than unconditional key sizes.
They are matched by field/type identity and retain their source locations.
For example, a factory assigning 4096 bits adds
`ciphertrail:key-size-bits:declared = 4096` and a `field-initializer` parameter
fact, without setting an unconditional `ciphertrail:key-size-bits` or native
parameter set on an unconstrained method. Zero-value receivers, later mutation, other constructions, and whether
the factory is ever called are not proven away.
Cipher-mode findings do not currently resolve their underlying block cipher.
TLS struct initializers record explicit minimum/maximum versions, client-auth
mode, and peer-verification configuration; subsequent mutations and implicit
runtime defaults are not evaluated.

All selected packages and functions are inventoried, including functions that
may never execute. This is not a whole-program reachability proof. `_test.go`
files, `testdata`, `vendor`, hidden directories, and `node_modules` are excluded;
ordinary source packages used only by tests are not automatically classified.
Standalone test harnesses containing ordinary Go files remain in scope unless
explicitly excluded, even when their directory is named `test` or `tests`.

### Declarative certificate configuration

Cryptography can be requested without directly calling `crypto/x509`.
CipherTrail recognizes resolved cert-manager `CertificateSpec` and
`CertificatePrivateKey` types in Go source, including aliases. Unrelated types
with the same short names are not treated as certificates.

These declarations produce configured certificate/key/algorithm assets linked
to their owning module and the resolved cert-manager API provider. Supported
settings include the requested key algorithm and size, encoding, rotation
policy, certificate lifetime, renewal interval, usages, issuer reference,
secret name, common name, and CA flag.

Constant fields and bounded, unambiguous initializer/copy patterns are resolved,
including private-key struct copies and `metav1.Duration` values. The resolver
can follow zero-argument, receiverless helpers with a single return statement
across selected source packages. Copies of private immutable settings can
resolve directly. Detected mutations, escapes, multiple assignments, parameterized
or branched helpers, recursion, and excluded definitions remain unresolved.

Exported mutable configuration is not treated as a guaranteed use-site value.
Where its initializer can be traced, `:declared` properties and structured
parameter evidence record the declared settings with their origins and
limitations. A private-key use site can link to its typed definition using a
`declaredPolicy` relationship; this means configuration provenance, not a policy
engine or compliance verdict. Imported variables without selected source
initializers remain unknown, even if their names resemble constants (such as
cert-manager's `RotationPolicyAlways`). No cert-manager defaults are assumed.
Absent initializer fields are omitted. Explicit fields whose values cannot be
resolved are listed in the occurrence's `unresolved` summary. Resolved declared
values have no companion `unknown` property. Literal values such as `false`, `0`,
and the string `"unknown"` remain ordinary known values.

Declaration evidence does not prove that a certificate was issued, deployed, or used; actual serial numbers,
validity timestamps, and fingerprints require artifact or runtime evidence.

Source exclusions apply to these declarations too. A reusable key configuration
may have its own declaration evidence as well as evidence at a certificate
specification that uses it; neither entry represents an observed private key.

### Excluding test helpers and fixtures

`_test.go` files and `testdata/` directories are excluded by the existing Go
scope rules. A normal file such as `internal/testutil/crypto.go` is still
ordinary Go source; CipherTrail does not guess that it is test-only from its
directory name.

Add literal source-relative file or directory paths to `.ciphertrailignore` at
the root passed to `--source`:

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
./bin/ciphertrail scan --source . \
  --exclude internal/testutil \
  --exclude test/fixtures \
  --output cbom.json
```

File and CLI exclusions are combined, normalized, and recorded as
`ciphertrail:source-exclusion-paths` in collection properties. Paths are anchored
to each source root and match complete path segments; `internal/testutil` does
not exclude `internal/testutilities` or `production/testutil`. Blank lines and
lines beginning with `#` are ignored. Glob patterns, negation, absolute paths,
and parent traversal are rejected rather than silently misinterpreted.

Only the `.ciphertrailignore` at the explicit source root is read; parent and
nested ignore files are not inherited. The file must be regular, not a symlink,
and no larger than 64 KiB.

Excluded packages and nested modules are removed from the scan roots.
Excluded files do not generate source findings or unmodeled-API notes, including
TLS configuration findings. This is an analysis-scope control, not a compilation
sandbox: files belonging to a retained package, and dependencies needed by
retained code, may still be read for Go type checking. Compilation errors in
required code remain errors.

These rules apply only to `--source` collection. They do not filter explicit
`--file`, `--image`, TLS, or SSH inputs: fixture material actually packaged or
deployed in those targets is still relevant inventory.

### Dependency preparation and read-only analysis

Source scans automatically prepare missing dependencies by default. Each
selected module is first checked against the local cache. If modules or
checksums are missing, CipherTrail prepares the selected packages using the
existing Go proxy, private-module, checksum-service, and VCS authentication
settings, then retries source analysis offline.

```sh
./bin/ciphertrail scan --source /path/to/repository --output cbom.json
```

Standalone modules use isolated alternate `go.mod`/`go.sum` files for dependency
preparation. Workspaces use an isolated `go.work`/`go.work.sum` and read-only
manifest overlays; package-aware preparation honors local workspace members.
Preparation does not run `go mod download all`, which can request unused
transitive versions and placeholders unrelated to the selected packages.
Local replacements continue to resolve against their original directories.
The target's manifests and checksum files are not modified. Preparation stops
rather than silently changing module requirements. It does not run tests,
`go generate`, or the target application.

Configure `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, and authentication as for a normal
Go build before scanning private repositories. CipherTrail preserves these
settings during preparation; it does not invent credentials or upload source
to a scanning service. Go/VCS interactive password prompts and automatic Go
toolchain downloads are disabled. Preparation is bounded to ten minutes per
attempt and respects cancellation.

Use `--offline` for strict cache-only operation:

```sh
./bin/ciphertrail scan --source /path/to/repository --offline --output cbom.json
```

In this mode, dependencies and checksums must be available locally. Isolated
checksum files can still be populated from cached modules, but network lookup
is disabled. `--offline` cannot be combined with TLS/SSH network probes.
It does not modify normal local file/image collection behavior.

`--include-dependencies` changes which collected components are exported.
`--include-nested-repos` changes source discovery scope. Neither flag controls
dependency downloads.

The build target is separate from dependency availability. By default Go uses
the host platform. For Linux-only code scanned on macOS, select its deployment
target explicitly rather than suppressing platform-specific compilation errors:

```sh
./bin/ciphertrail scan --source /path/to/repository \
  --goos linux --goarch amd64 --output cbom.json
```

If preparation or loading fails, the report remains incomplete and the command
exits 1. Invalid module versions, unavailable private credentials, checksum
failures, and incompatible local toolchains still require correction; they are
not converted into empty successful scans.

For package-load problems, CipherTrail groups failures by safe cause and reports
the affected package count and an example location, instead of repeating a
numeric error kind for every import. For example, `module lookup disabled by
GOPROXY=off` means the offline cache is missing a required module version, not
that the cryptographic analyzer rejected an algorithm. Checksum, module-metadata,
syntax, and type-checking failures are reported separately.

The complete list of affected packages, positions, module directories, cause
categories, and preparation hints is retained in collection properties as
`ciphertrail:package-load-errors`. Arbitrary compiler messages are not copied
into reports because they can contain source literals or credential-bearing
URLs. Unclassified failures direct you to the module's normal Go build/list
diagnostics. Collection properties record `ciphertrail:dependency-mode` and
`ciphertrail:dependency-preparation` outcomes. Preparation metadata does not
include credentials or proxy URLs.

Loading packages can invoke the local Go compiler and native build tools to
obtain export information, but does not run tests, `go generate`, or the target
application. The analysis phase disables module network lookups and uses
`-mod=readonly`; source is not uploaded as a fallback.

## Runtime interrogation

Probe only endpoints you are authorized to interrogate. CipherTrail never
discovers targets automatically. These examples are commands for the operator
to run; tests use loopback fixtures only.

```sh
./bin/ciphertrail scan \
  --tls service.example:443 \
  --ssh host.example:22 \
  --timeout 5s \
  --output runtime.cbom.json
```

TLS verifies the peer using normal trust roots by default. Supply custom roots,
SNI, and an mTLS identity when needed:

```sh
./bin/ciphertrail scan \
  --tls 192.0.2.10:8443 \
  --server-name service.example \
  --ca-file ca.pem \
  --client-cert client.pem \
  --client-key client-key.pem \
  --output runtime.cbom.json
```

`--tls-insecure` explicitly disables TLS peer verification to observe an
otherwise untrusted endpoint. The report marks that observation as unverified.
This option is not a trust or compliance assessment.
TLS credential inputs must be regular files no larger than 16 MiB.

SSH verifies the host's key-exchange signature through the SSH implementation,
but does not establish known-host trust. The callback captures the public host
key and intentionally aborts before user authentication. An RSA key's
`ssh-rsa` encoding is **not** reported as evidence of a negotiated SHA-1
signature. SSH cipher/signature negotiation and server capability enumeration
are not inventoried in this MVP.

The probe's Go TLS/SSH negotiation defaults constrain what can be observed.
A failed handshake is a collection failure, not a cryptographic policy verdict.
There is no process attachment, eBPF instrumentation, Kubernetes discovery, or
automatic retrieval of cluster Secrets.

## Artifact inventory

Supported public metadata sources include:

- PEM/DER X.509 certificates and PKIX, PKCS#1, SEC1, and PKCS#8 keys.
- OpenSSH private keys and authorized/public-key entries, where supported by the
  Go SSH library.
- RSA, ECDSA, Ed25519, and supported ECDH public-key parameters.
- Encrypted private-key containers, recorded with unresolved algorithm/size
  summaries and an explicit no-decryption diagnostic rather than decrypted.
- Go executable build/module information. Linker flags and arbitrary build
  settings are excluded to avoid exporting embedded secrets.
- OpenSSL `.cnf` protocol, cipher-selector, group, and signature declarations.
  Includes, variables, selector expressions, and section activation are not
  evaluated.

File contents, private keys, passwords, and arbitrary source strings are not included
in reports. Key fingerprints are derived from public-key encodings only.
Reports still contain sensitive operational metadata such as paths, endpoint
names, certificate identities, and dependency versions; keep them internal.

Image collection respects whiteouts and opaque directories. It streams the
effective filesystem without extracting image paths to disk or following
links. Local artifact directory scans do not follow symlinks either, and report
those omissions. OCI TAR archives, multi-image Docker TARs, registry pulls,
JKS/PKCS#12 stores, and general native-binary cryptographic disassembly are not
supported yet. Native binaries without Go build information are identified as
analysis limitations.

In-memory asset parsing is limited to 256 MiB per file. Oversized image assets
produce errors rather than silently disappearing. Local Go binaries use
random-access build-info reads rather than loading the whole executable.

## Output and exit behavior

Every generated report is validated against bundled CycloneDX 1.7 JSON Schemas,
without network access. Standard `cryptoProperties`, software dependencies, and
evidence occurrences carry the inventory. Each native occurrence has a stable,
BOM-wide unique `bom-ref`; its location, line, and symbol are recorded only there.
Namespaced properties add:

- `ciphertrail:provenance`: an `occurrence` reference, `present` / `configured` /
  `observed` classification, collector, observation time when applicable, and
  an optional `unresolved` parameter-name summary. Qualified parameter facts
  are grouped by shared `basis` and `limitation`; each group's `values` retain
  their names, values, and definition locations. Definition locations describe
  parameter origins, not duplicate copies of the asset's use site.
- `ciphertrail:collection`: requested target, outcome, collector properties
  (including Go build context, analysis scope, and detailed package-load
  problems), errors, and limitations.
- `ciphertrail:collection-status`: whether the requested collectors succeeded.
- `ciphertrail:output-scope`: `crypto-focused` or `full-dependencies`.
- `ciphertrail:omitted-components`: number of collected components excluded by
  the output scope.
- Resolved public parameters and qualified `:declared` alternatives. Missing
  parameters are not replaced with invented values or defaults.

Supplemental provenance is associated with its own occurrence, so declarations
from one location cannot hide unresolved parameters or observations elsewhere.
Evidence without a location remains component-scoped; no occurrence is invented,
and a symbol is retained in supplemental provenance if one was supplied.
Repeated generic source-analysis caveats belong to collection scope metadata.

For example, a decoded `ciphertrail:provenance` property can contain:

```json
{
  "occurrence": "urn:ciphertrail:<occurrence-hash>",
  "kind": "configured",
  "collector": "go",
  "unresolved": ["cert-manager.common-name", "cert-manager.secret-name"],
  "parameters": [
    {
      "basis": "declared-policy-initializer",
      "limitation": "declared configuration only; exported mutable policy may change before use",
      "values": [
        {
          "name": "cert-manager.duration",
          "value": "720h0m0s",
          "location": "pkg/certpolicy/client.go",
          "line": 40
        }
      ]
    }
  ]
}
```

This replaces the former `ciphertrail:evidence` property. Consumers should join
`provenance.occurrence` to `evidence.occurrences[].bom-ref`, read grouped
`parameters[].values`, and use `unresolved` rather than testing property values
for the string `"unknown"`. Existing reports can be replaced by rescanning.
The output remains CycloneDX 1.7; no compatibility flag is required.

The complete schema bundle, including `cryptography-defs.schema.json`, is pinned
to the official 1.7 release. Generation and validation target 1.7 only.
Existing CipherTrail 1.6 reports can be replaced by rerunning the same scan;
there is no version-conversion step that might discard or change assets.

The 1.7 output uses native `certificateProperties.serialNumber` instead of the
former `ciphertrail:certificate-serial-number` property. Curves use
`algorithmProperties.ellipticCurve` with canonical identifiers such as
`nist/P-256`, `other/Ed25519`, and `other/Curve25519`. Certificates, keys, and
protocols use `relatedCryptographicAssets` for their relationships, with explicit
roles (`publicKey`, `signatureAlgorithm`, `algorithm`, and `certificate`).
All these references participate in graph validation and crypto-focused pruning.
Certificate component hashes remain SHA-256 over the full DER certificate;
private-key material and private-key digests are not exported.

Stable component references and sorted relationships make reports comparable.
Observation/report timestamps vary between runs. Collection success does not
mean exhaustive discovery or a secure configuration.

| Exit | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | Collectors succeeded; declared limitations and unknowns may remain    |
| 1    | Collection, schema validation, or output failed                       |
| 2    | Invalid command, flags, input combination, or endpoint syntax         |

When one collector fails, successfully collected evidence is retained in a
schema-valid partial report and the command exits 1. No algorithm choice,
certificate expiry, or key size causes a policy exit.

Named output files are written atomically with owner-only permissions.
CipherTrail refuses to overwrite explicit inputs, credentials, symlinks,
special files, or unrelated existing files. It can replace a previous
CipherTrail CBOM, provided that file did not change during collection.
Shell redirection is outside these protections: never redirect stdout onto an
input file.

## Development and extension

```sh
make test
make check
make build
```

Tests cover graph pruning/reference closure, optional full inventory,
source symbols/parameters, offline workspaces, nested modules,
TLS/mTLS, SSH pre-authentication termination, timeouts, asset privacy, image
whiteouts/traversal, output safeguards, and official schema validation.

Collectors implement `inventory.Collector` and return `inventory.Result`.
Evidence, relationships, and export are shared; another language can add a
collector without changing the format or introducing policy logic.
`Entry.Parent` denotes ownership; `Result.DependOn` records ordinary dependencies.
Dependencies from cryptographic assets identify required implementation context.
Collector properties and diagnostics survive output pruning.

- `internal/goscan`: Go discovery, rules, and value analysis.
- `internal/material`: public certificate/key metadata.
- `internal/probe`: explicit TLS and SSH collectors.
- `internal/artifact`: files, binaries, OpenSSL declarations, and images.
- `internal/inventory`: shared model, stable references, and validated export.
- `internal/cli`: input orchestration and protected output.

The bundled schemas retain their upstream license and attribution in
`internal/inventory/schema/`.
