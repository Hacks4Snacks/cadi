# CipherTrail

Cryptography discovery, backed by evidence.

CipherTrail is a Go-first CLI that generates CycloneDX 1.7 cryptographic bills of
materials (CBOMs) from source code, local artifacts, and explicit runtime
endpoints. It does not score risk, enforce cryptographic policy, claim
compliance, or remediate findings.

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

The module path is `ciphertrail` for local development. Publishing under a
repository namespace requires updating the module path and internal imports.

## Inputs and analyzers

The canonical command is `ciphertrail scan PATH...`. Directories are mixed
repository roots; files are explicit passive inputs. Go, Python, Kubernetes,
and artifact analysis run where applicable and contribute to one CBOM.
Repositories without Go modules or Python source record `not-applicable` for
those analyzers rather than requiring their language tooling.

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

| Input                  | Evidence collected                                             | Important boundary                                          |
|------------------------|----------------------------------------------------------------|-------------------------------------------------------------|
| Go source              | Resolved crypto API calls, parameters, modules, dependencies   | Configuration evidence, not proof of execution              |
| Python source          | Import-qualified crypto calls and bounded parameter facts      | Static AST analysis; no target imports or execution         |
| Local files            | Public material, Go binary metadata, supported configuration   | No private-key values; no target program execution          |
| Local image            | Effective filesystem using the same file detectors             | Single-image Docker save TARs and OCI layout directories    |
| Kubernetes manifests   | Certificate declarations, TLS Secret material, Ingress TLS     | Local YAML/JSON only; no Helm execution or cluster access   |
| TLS target             | Negotiated version/cipher, peer certificate chain, ALPN        | One handshake, not exhaustive capability enumeration        |
| SSH target             | Public host key, key format, size/curve, fingerprint           | Stops before user authentication; no commands or login      |

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

Flags may appear before or after paths. Use `--` before a path beginning with `-`:

```sh
./bin/ciphertrail scan . --goos linux --goarch amd64 --tags production
```

Without `--output`, JSON goes to stdout. Coverage summaries, grouped diagnostics,
and operational errors go to stderr. Overlapping paths are normalized and shared
file/module work is deduplicated without merging distinct evidence contexts.

For a human-readable crypto-focused view alongside the complete JSON report:

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

## Crypto-focused output

By default, the report contains:

- Cryptographic assets and their evidence.
- Ownership context, including enclosing applications, container images, and
  Kubernetes configuration resources.
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

A directory root is scanned as one repository. Discovery stops at nested
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
./bin/ciphertrail scan ./project ./project/other-repository
./bin/ciphertrail scan ./project --include-nested-repos
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
fact, without setting an unconditional native parameter set on an unconstrained
method. Zero-value receivers, later mutation, other constructions, and whether
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

### Shared repository exclusions

Repository discovery excludes hidden metadata directories and common output,
dependency, and fixture directories: `vendor`, `node_modules`, `testdata`, `test`,
`tests`, `mocks`, `samples`, `examples`, `bin`, `out`, `dist`, `build`, `target`,
`coverage`, and `__pycache__`. The selected root itself is not excluded by its
name. Recognized CBOM/SBOM files and the requested output file are excluded so
generated inventories are not recursively scanned.

Child directories marked by `pyvenv.cfg` are omitted as Python virtual
environments, without reading their configuration or dependencies. An ordinary
directory named `env` is not excluded just because of its name.

Go also excludes `_test.go` files through its build context. A normal file such
as `internal/testutil/crypto.go` is still
ordinary Go source; CipherTrail does not guess that it is test-only from its
directory name.

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
chart roots, and deduplication counts in the collection's `ciphertrail:scope`
property. Paths are anchored to each directory root and match complete path
segments; `internal/testutil` does
not exclude `internal/testutilities` or `production/testutil`. Blank lines and
lines beginning with `#` are ignored. Glob patterns, negation, absolute paths,
and parent traversal are rejected rather than silently misinterpreted.

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

### Dependency preparation and read-only analysis

Source scans automatically prepare missing dependencies by default. Each
selected module is first checked against the local cache. If modules or
checksums are missing, CipherTrail prepares the selected packages using the
existing Go proxy, private-module, checksum-service, and VCS authentication
settings, then retries source analysis offline.

```sh
./bin/ciphertrail scan /path/to/repository --output cbom.json
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
./bin/ciphertrail scan /path/to/repository --offline --output cbom.json
```

In this mode, dependencies and checksums must be available locally. Isolated
checksum files can still be populated from cached modules, but network lookup
is disabled. `--offline` cannot be combined with TLS/SSH network probes.
It does not modify normal local file/image collection behavior.

`--include-dependencies` changes which collected components are exported.
`--include-nested-repos` changes repository discovery scope. Neither flag controls
dependency downloads.

The build target is separate from dependency availability. By default Go uses
the host platform. For Linux-only code scanned on macOS, select its deployment
target explicitly rather than suppressing platform-specific compilation errors:

```sh
./bin/ciphertrail scan /path/to/repository \
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

## Python analysis

Python source is discovered alongside other repository content; no `pyproject.toml`
or installed project environment is required. Individual `.py` files are also
valid source inputs, including files with no recognized cryptography:

```sh
./bin/ciphertrail scan ./service ./rendered.yaml --output service.cbom.json
./bin/ciphertrail scan ./service --analyzers python --output python.cbom.json
./bin/ciphertrail scan ./service/crypto.py --analyzers python
```

The Go collector runs an embedded, trusted AST frontend with
`python3 -I -S -B`. Source bytes are input data: project modules, startup hooks,
annotations, and statements are never imported or executed. No `pip` operation
or dependency download is performed. An interpreter resolving inside the scanned
source tree is rejected; use a trusted interpreter outside that tree on `PATH`.
Python analysis never uses an interpreter from an image.

### Initial API coverage

- Standard library: common `hashlib` hashes, named hash selection, PBKDF2/scrypt,
  HMAC, `secrets`, and `os.urandom`.
- `ssl`: context creation, wrapping APIs, declared TLS minima/maxima, verification
  settings, OpenSSL cipher selectors, and certificate/key/CA file references.
  These are configured settings, not negotiated versions or cipher suites.
- `cryptography`: common hash/HMAC APIs; RSA, EC, Ed25519/Ed448, and X25519/X448
  key generation; supported signature operations; AES and common block modes,
  AEAD and Fernet; PBKDF2/HKDF/scrypt; X.509 imports and certificate/CSR builder
  signing; and private/public key imports.
- `Crypto` and `Cryptodome`: common hash/HMAC constructors, AES configuration
  and encryption/decryption entry points, RSA/ECC generation, and random bytes.
- HTTP clients: selected Requests, HTTPX, urllib3, and standard-library request
  APIs with an established HTTPS scheme.

Coverage is an explicit API model set, not complete coverage of those libraries.
Resolved but unmodeled crypto APIs produce file/line diagnostics. Known metadata
and lifecycle calls are classified by exact symbol rather than broad method-name
suppression. Algorithms are not inferred from arbitrary function names.

### HTTP clients and URL schemes

HTTPS intent is collected from:

- Requests verb helpers and `request`, including imported aliases and known
  `Session` instances.
- HTTPX verb helpers, `request`, and `stream`, including `Client` and
  `AsyncClient`. Known synchronous/asynchronous context-manager bindings are
  supported.
- urllib3 `request`, pool/proxy manager request methods, and explicit
  HTTPS connection-pool construction/use.
- `urllib.request.urlopen`, `Request` URL wrappers, opener `open` calls, and
  `http.client.HTTPSConnection` construction/use.

The resolver retains only a bounded string prefix for scheme analysis. Literal
URLs, fixed f-string prefixes, and concatenations of known string forms can
establish HTTPS. For example, `f"https://example.invalid/{resource_id}"` has an
established scheme without resolving or exporting the interpolation. An opaque
operand in string concatenation is not assumed to be a string.

Relative HTTPX request URLs can inherit a known constructor `base_url`; an
opaque request URL cannot, because it might override the base with an absolute
URL. Observed URL/base mutations, provider shadowing, method/constructor
replacement, and opaque context-manager results prevent unsupported inference.
Known `httpx.URL` and `urllib.request.Request` wrappers are inspected as source
expressions only.

An established HTTPS operation produces a **configured** TLS asset with source
evidence and an import-namespace provider link. Plain HTTP produces no TLS
asset. Opaque, relative-without-known-base, or unsupported URL schemes produce a
file/line diagnostic instead of a guessed protocol. Prepared-request `send`
calls are currently reported as unresolved. Byte URLs, `%` formatting,
`str.format`, and dynamic leading f-string fields remain unresolved.

These findings describe initial HTTPS intent, not runtime transport behavior.
Redirects, proxies, custom transports, negotiated TLS versions/ciphers, peer
certificates, and verification defaults are not inferred. URLs, hosts, paths,
query parameters, headers, cookies, authentication values, bodies, and
HTTP-client certificate arguments are not exported or used in asset identity.
No requests are made and no client libraries are imported or installed.

### Resolution, evidence, and limits

Direct, `from`, and aliased imports are resolved with lexical binding checks.
Parameters, rebinding, wildcard imports, local provider-named modules, and
observed namespace or instance attribute mutations prevent unsupported
attribution. Provider shadow files are checked by filesystem metadata even when
their contents are excluded. Mutation facts from selected files also invalidate
nested parameter expressions, not just the outer API call.

Literal integer expressions, immutable byte lengths, simple aliases, and selected
constructor results can establish public parameters. These describe visible
source configuration, not a runtime guarantee. Opaque calls, mutable byte arrays,
dynamic lookup, arbitrary side effects, and cross-module value/wrapper tracing
remain outside this bounded analysis. Unresolved parameters stay in provenance;
unknown-value placeholder properties are not emitted.

Every finding retains its Python source location, line, and resolved API symbol.
Provider links identify import namespaces, not installed distributions or
versions: in particular, `Crypto` does not uniquely identify PyCryptodome.
The frontend interpreter version is collection metadata, not the target runtime
version. Python dependency manifests and lockfiles are not an installed-package
inventory.

Keys, messages, passwords, inline certificate contents, and other raw argument
values are not exported or used to form private-derived identifiers. Only modeled
public fields and lengths are retained. Referenced certificate/key paths are
not opened, and certificate signing declarations are not issued certificates.

Parsing is bounded to 8 MiB per source file, 100,000 AST nodes, 32 expression
levels, 200,000 resolved value visits, 64 arguments per call, and a 16 MiB frontend
response. Each file has a 10-second frontend deadline and supports cancellation.
Syntax, source-encoding, interpreter, and resource-limit errors are operational
failures: successful files remain in the partial CBOM with failed coverage.
The host interpreter must understand the selected source syntax; Python 3.10 is
the frontend minimum, not a promise that it parses every newer Python release.
Stubs, notebooks, bytecode, Python embedded in YAML or shell, and source analysis
inside images are not included.

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
- Supported Kubernetes YAML/JSON declarations and embedded TLS material, using
  the same detector as explicit manifest scans.

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

## Kubernetes and rendered Helm manifests

Supply rendered Kubernetes YAML/JSON as a PATH input. Use `--analyzers kubernetes`
when only configuration analysis is wanted, or combine it with a repository:

```sh
./bin/ciphertrail scan ./rendered.yaml --offline --output manifests.cbom.json
./bin/ciphertrail scan ./service ./manifests --output service.cbom.json
```

Repository and image scans register Kubernetes detection when that analyzer is
selected. Repository discovery identifies Helm charts and defers their raw
template files; it does not execute charts or contact clusters. Artifact files
such as chart trust stores are still inspected. Add the rendered output as another
PATH input. An explicitly selected individual template can be inspected, but any
unresolved Helm expressions remain coverage limitations.

Supported resources:

| Resource                                             | Inventory treatment                                                                  |
|------------------------------------------------------|--------------------------------------------------------------------------------------|
| `cert-manager.io/v1 Certificate`                     | Requested X.509/key configuration, algorithm/size, lifetime, renewal, usages, issuer |
| `v1 Secret`, type `kubernetes.io/tls`                | Public metadata parsed from `tls.crt` and `tls.key`; private bytes are never output  |
| `networking.k8s.io/v1 Ingress`                       | Explicit TLS entries and declared Secret references; no negotiated protocol claim    |
| `v1 List` and supported typed Lists                  | Each item analyzed with its own resource identity and JSON-pointer field location    |
| `v1 ConfigMap`                                       | Typed YAML/JSON and PEM inside `data` or base64 `binaryData`, with nested provenance |
| CAPI kubeadm resources, v1beta1/v1beta2              | TLS/CA settings and inline bootstrap file contents                                   |
| kubeadm configuration, v1beta3/v1beta4               | Explicit cluster/init/join TLS and certificate configuration                         |
| `apiserver.config.k8s.io/v1 EncryptionConfiguration` | Ordered encryption providers and declared key references                             |

Multi-document YAML and JSON resources are supported. Kubernetes objects require
`metadata.name`; configuration documents such as EncryptionConfiguration do not.
Runtime-substituted identities in embedded profiles and CAPI bootstrap resources
stay unresolved without suppressing known settings. An omitted namespace stays
unspecified rather than being assumed to be `default`. Absent configuration fields
do not receive invented defaults. Secret and issuer references are declarations:
the detector does not look up their targets, prove they exist, or validate an issuer chain.

For TLS Secrets, `stringData` overrides the corresponding `data` field, matching
Kubernetes merge semantics. Base64 decoding and material parsing happen locally;
unrelated Secret keys and non-TLS Secret contents are not inspected. Embedded
certificates and keys are `present` evidence, not runtime observations. Missing
or templated TLS material stays unresolved; malformed material fails the
collection while preserving valid findings from other fields or documents.
The detector does not validate key/certificate pairing or Kubernetes admission.

Render Helm charts separately in your existing build workflow, then supply the
rendered output. CipherTrail does not invoke Helm, fetch chart dependencies,
evaluate `lookup`, or reconstruct values files and rendering flags. Recognized
`# Source: chart/templates/file.yaml` comments are retained as origin metadata.
Unrendered resource identities/directives produce explicit scope notes;
unresolved template expressions in supported fields are omitted and recorded
without suppressing other resolved fields.

### Embedded configuration and bootstrap profiles

Rendering resolves Helm expressions, not every later substitution. A rendered
ConfigMap can still hold a YAML stream containing CAPI resources, cloud-init
expressions, and bootstrap files. CipherTrail follows those structured layers:

- ConfigMap `data` and base64 `binaryData` values containing typed YAML/JSON.
- `KubeadmControlPlane.spec.kubeadmConfigSpec`,
  `KubeadmConfigTemplate.spec.template.spec`, and `KubeadmConfig.spec`.
- Inline bootstrap `files[].content`, including explicit base64 encoding.
  Other or unresolved encodings produce coverage notes rather than being guessed.
- Standalone or nested kubeadm `ClusterConfiguration`, `InitConfiguration`, and
  `JoinConfiguration`, plus apiserver `EncryptionConfiguration`.

The bootstrap models record TLS minimum versions and configured cipher suites
for the API server, controller manager, scheduler, etcd, and init/join kubelets.
Both argument maps and name/value lists are supported. TLS and encryption
configuration file references remain references; the scanner does not open those
paths on the scanning host. Duplicate crypto arguments stay ambiguous.

Explicit CA/leaf validity settings and supported `encryptionAlgorithm` values are
inventoried without assuming kubeadm defaults or manufacturing certificate expiry
dates. Cloud-init/Jinja or `${VARIABLE}` substitutions in unrelated fields do not
hide resolved crypto settings. Unresolved identities and parameters retain
uncertainty without exporting their expression bodies.

EncryptionConfiguration supports `secretbox` (XSalsa20-Poly1305), `aesgcm`
(AES-GCM), and `aescbc` (AES-CBC with PKCS#7). Resource selection, provider order,
declared key names, and key order are preserved. The first provider's first key
is the configured write key; subsequent providers/keys are read fallbacks.
`identity` is recorded as passthrough context, not a fictitious crypto algorithm.
Provider ordering follows the
[Kubernetes encryption configuration contract](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/).

Symmetric key values are not inspected, serialized, or hashed. Key sizes remain
unresolved; a configured key name is not observed key material. KMS implementations
are not analyzed and do not receive guessed algorithms. These declarations do not
prove that the configuration was activated or that stored data was re-encrypted.

PEM material in supported embedded payloads reuses the public-only material
parser. Arbitrary ConfigMap values are not copied into the report. Shell/Python
bodies, `contentFrom` Secret retrieval, and script-generated substitutions or
secret-to-file bindings remain outside this analysis. In particular, this does
not infer LUKS/cryptsetup behavior from shell scripts.

Structured provenance includes:

- `context.document`: one-based YAML/JSON document number.
- `context.resource`: API version, kind, name, and namespace when supplied.
- `context.field`: a JSON pointer, including List item and TLS entry indices.
- `context.renderedFrom`: a recognized Helm source marker, when present.
- `context.contentLine`: the line inside decoded PEM content, when applicable.
- `context.unresolved`: unresolved resource identity fields.
- `context.embedded`: an ordered chain of inner document/resource/field/line
  positions, declared virtual `file` paths, and unresolved identity/path fields.

The native occurrence line still identifies the containing YAML/JSON field;
decoded YAML or PEM line numbers do not overwrite that source location. For
example, an encryption-provider finding can retain its outer ConfigMap data field,
the embedded CAPI profile's file-content field, and the provider's position inside
the declared bootstrap file.

Parsing is bounded to 16 MiB per document payload, eight decoded embedding levels,
32 MiB of cumulative root/decoded content, 64 levels of YAML structure, and a shared
100,000-node budget per input file. Duplicate mapping keys are rejected; YAML
aliases and merge keys are explicitly unsupported. Parser error messages do not
include raw input snippets. Top-level unsupported Kubernetes kinds produce
coverage notes; unrelated embedded kinds are summarized in collection metadata.
Neither is treated as discovered cryptography. This is configuration inventory,
not a Kubernetes validator, policy engine, or live-cluster scanner.

## Output and exit behavior

Every generated report is validated against bundled CycloneDX 1.7 JSON Schemas,
without network access. Standard `cryptoProperties`, software dependencies, and
evidence occurrences carry the inventory. Each native occurrence has a stable,
BOM-wide unique `bom-ref`; its location, line, and symbol are recorded only there.
Namespaced properties add:

- `ciphertrail:evidence-kind` and `ciphertrail:collector`: flat classification
  and collector fields when every evidence record for a component is simple
  and agrees on both values. These apply to all of its native occurrences.
- `ciphertrail:provenance`: occurrence-linked records when evidence has differing
  classifications/collectors or additional detail: observation time, a
  location-free symbol, source context, unresolved parameters, or declaration
  facts. These retain `present` / `configured` / `observed` classification, collector, and
  an optional `unresolved` parameter-name summary. Qualified parameter facts
  are grouped by shared `basis` and `limitation`; each group's `values` retain
  their names, values, and definition locations. Definition locations describe
  parameter origins, not duplicate copies of the asset's use site. Structured
  inputs also carry optional resource/document/field `context`.
- `ciphertrail:collection`: requested target, outcome, collector properties
  (including Go build context, analysis scope, and detailed package-load
  problems), errors, limitations, and typed analyzer `coverage`.
- `ciphertrail:collection-status`: whether the requested collectors succeeded.
- `ciphertrail:output-scope`: `crypto-focused` or `full-dependencies`.
- `ciphertrail:omitted-components`: number of collected components excluded by
  the output scope.
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

Detailed supplemental provenance is associated with its own occurrence, so declarations
from one location cannot hide unresolved parameters or observations elsewhere.
Evidence without a location remains component-scoped; no occurrence is invented,
and a symbol is retained in supplemental provenance if one was supplied.
Repeated generic source-analysis caveats belong to collection scope metadata.

Each coverage record identifies its analyzer, status, inspected files/modules,
cryptographic finding count, skipped inputs, and any preparation reason.
Statuses distinguish `completed`, `failed`, `not-applicable`, `needs-rendering`,
and `deduplicated`. A completed analyzer can still have skipped templates or
unmodeled APIs; its counts and detailed diagnostics do not imply exhaustive
cryptographic coverage. Source build-context options require the `go` analyzer.

Stderr contains one coverage summary per input. Identical diagnostic messages
are grouped with an occurrence count; every original location remains in the
CBOM. Exclusions and recognized report files are listed in `ciphertrail:scope`,
not printed as hundreds of individual notes.

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

Consumers should read the flat classification for simple components. For detailed
records, join `provenance.occurrence` to `evidence.occurrences[].bom-ref`, read
grouped `parameters[].values`, and use `unresolved` rather than testing property
values for the string `"unknown"`. The optional `--summary` understands both
forms. Existing reports can be replaced by rescanning.
The output is CycloneDX 1.7.

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
whiteouts/traversal, multi-document Kubernetes manifests, embedded Secret
privacy, detector registration, input parity, output safeguards, and official
schema validation. A bounded manifest fuzz target also checks that malformed
inputs retain schema-valid partial inventories.

The project remains one Go module and executable. Input acquisition, file
detection, project analysis, active interrogation, orchestration, and export are
separate boundaries:

- [`internal/input`](internal/input): read-only local traversal and effective
  image streams, file lifetimes, bounded buffering, and optional random access.
- [`internal/scope`](internal/scope): shared discovery snapshots, literal
  exclusions, repository boundaries, generated-report filtering, and Helm scope.
- [`internal/detect`](internal/detect): the file-detector contract and dispatch.
- [`internal/detect/artifact`](internal/detect/artifact): material, OpenSSL, and
  Go binary recognition independent of the input provider.
- [`internal/detect/kubernetes`](internal/detect/kubernetes): typed local
  configuration detection; no Kubernetes client or Helm runtime.
- [`internal/goscan`](internal/goscan): project-wide Go loading, SSA, and value
  analysis, kept separate from single-file detectors.
- [`internal/pyscan`](internal/pyscan): isolated Python AST facts, import/binding
  resolution, Go-owned crypto models, and source coverage.
- [`internal/material`](internal/material): shared public certificate/key
  metadata parsing, reused by file, manifest, image, and runtime collection.
- [`internal/probe`](internal/probe): explicitly authorized TLS/SSH interrogation.
- [`internal/scan`](internal/scan): validated requests, built-in composition,
  normalized/deduplicated planning, execution, cancellation, and coverage.
- [`internal/inventory`](internal/inventory): evidence, ownership, relationships,
  stable references, and reusable configuration constructors.
- [`internal/export/cyclonedx`](internal/export/cyclonedx): graph selection,
  occurrence/provenance serialization, and offline schema validation.
- [`internal/cli`](internal/cli): flags, presentation, exit codes, protected output.

To add a file detection type:

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
[`internal/export/cyclonedx/schema`](internal/export/cyclonedx/schema).
