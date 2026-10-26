# Go source analysis

[Home](../README.md) | [Scanning and exclusions](scanning.md) | [CBOM output](output.md)

The analyzer discovers nested modules, loads the selected build context using
Go's type checker, and uses SSA to identify actual cryptographic symbols.
Aliases do not defeat recognition, and unrelated functions with similar names
are not treated as cryptography.

```sh
./bin/cadi scan /path/to/repository \
  --analyzers go --goos linux --goarch amd64 --output go.cbom.json
```

See [repository boundaries](scanning.md#repository-boundaries) and
[shared exclusions](scanning.md#shared-repository-exclusions) to control scope.

## Cryptographic API models

Recognizers cover common constructors and operations in these API families:

- RSA, AES, DES/3DES, ECDSA, Ed25519, ECDH/X25519, ML-KEM, and ML-DSA selection/key generation.
- MD4/MD5, RIPEMD-160, SHA-1, SHA-2, SHA-3, SHAKE constructors, fixed-size BLAKE2
  operations, and `crypto.Hash.New` selection.
- HMAC, HKDF, PBKDF2, bcrypt, scrypt, and Argon2.
- ChaCha20, ChaCha20-Poly1305, and XChaCha20-Poly1305.
- Block-cipher mode constructors, including CBC, CTR, and GCM.
- AEAD encryption/authentication and decryption/verification, block-mode
  operations, and NaCl XSalsa20-Poly1305 secretbox operations.
- Generic signer/decrypter interfaces, block encryption/decryption, and stream
  operations.
- X.509 certificate/key operations, certificate requests, TLS entry points,
  TLS configuration initializers, and SSH key/connection APIs.
- Elliptic-curve selection, public-key access, X.509 certificate-pool imports,
  explicit TLS handshakes, and SHA-256 SSH public-key fingerprinting.

This is a recognizer list, not a claim that every method in those packages is
modeled. Unmodeled calls in cryptographic packages still produce diagnostics,
including the source file and line. Metadata and lifecycle helpers are classified
by exact package, receiver type, and method name; they are not coverage gaps and
do not create fictitious cryptographic assets.

| APIs                                                                                              | Inventory treatment                                                                                                        |
|---------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| `elliptic.P224/P256/P384/P521`                                                                    | Selected curve; no inferred signing or key-agreement use                                                                   |
| `crypto.Hash.New`                                                                                 | Hash operation; a resolved hash identifier supplies native facts, not proof of registration or availability                |
| `cipher.AEAD.Seal/Open`                                                                           | Authenticated encryption/decryption intent; opaque receiver algorithms and key sizes remain unknown                        |
| `cipher.AEAD.NonceSize/Overhead`                                                                  | Metadata access; no new asset                                                                                              |
| `cipher.BlockMode.CryptBlocks`                                                                    | Block operation; CBC direction is identified only from a visible matching constructor                                      |
| `mldsa.MLDSA44/MLDSA65/MLDSA87`, `mldsa.GenerateKey`                                              | ML-DSA parameter selection and key generation; no security-level or execution claim                                        |
| `nacl/secretbox.Seal/Open`                                                                        | XSalsa20-Poly1305 encryption/tagging or decryption/verification; fixed 256-bit key and 192-bit nonce sizes                 |
| `crypto.Signer.Public`, `crypto.Decrypter.Public`                                                 | Public-key access; runtime algorithm and key size remain unknown                                                           |
| `ecdh.PrivateKey.PublicKey`, `ssh.CryptoPublicKey` method                                         | Public-key access; no fabricated key bytes or size                                                                         |
| `ecdsa.PrivateKey.Public`, `mldsa.PrivateKey.PublicKey`                                           | Public-key access with known API family; material and runtime parameters remain unknown                                    |
| `mldsa.PublicKey.Parameters`, `mldsa.Parameters.String`                                           | Metadata access/formatting; no new asset                                                                                   |
| `ssh.FingerprintSHA256`                                                                           | SHA-256 digest for fingerprinting, not an SSH signature algorithm                                                          |
| `ssh.MarshalAuthorizedKey`, `ssh.PublicKey.Marshal`                                               | Public-key serialization; no key material or inferred key size exported                                                    |
| `ssh.PublicKey.Verify`                                                                            | Configured signature verification; signature algorithm, key size, and success remain unestablished                         |
| `ssh.Unmarshal`                                                                                   | Generic SSH wire-format decoding; not a cryptographic asset or evidence of an SSH connection                               |
| `rsa.PrivateKey.Validate`                                                                         | Structural private-key check; no validity or compliance verdict                                                            |
| `x509.CertificateRequest.CheckSignature`                                                          | CSR self-signature verification; no assumed algorithm or outcome                                                           |
| `x509.Certificate.CheckSignatureFrom`                                                             | Certificate signature verification against a supplied issuer; no assumed algorithm or complete trust chain                 |
| `x509.Certificate.Verify`                                                                         | Configured certificate-chain validation; no success, trust, or revocation-checking claim                                   |
| `x509.Certificate.VerifyHostname`                                                                 | Hostname matching against certificate metadata; no new cryptographic asset                                                 |
| `x509.Certificate.Equal`                                                                          | Certificate identity comparison; no new asset                                                                              |
| `x509.CertPool.AppendCertsFromPEM/AddCert`                                                        | Certificate import; actual certificates and trust remain unknown                                                           |
| `x509.SystemCertPool`                                                                             | Configured system-certificate loading; no host trust-store reads, certificate enumeration, or trust verdict by the scanner |
| `tls.Conn.Handshake`, `HandshakeContext`                                                          | Configured TLS handshake, not observed protocol/cipher negotiation                                                         |
| `tls.NewListener`                                                                                 | Configured TLS listener; no negotiated version/cipher or deployment claim                                                  |
| `elliptic.Curve.Params`, `CurveParams.Params`                                                     | Metadata access; no new asset                                                                                              |
| `ecdh.PublicKey.Curve`, `ssh.PublicKey.Type`                                                      | Metadata access; no new asset                                                                                              |
| `x509.SignatureAlgorithm.String`, `pkix.Name.String`                                              | Formatting only; no new asset                                                                                              |
| `tls.ClientAuthType.String`, `tls.CipherSuiteName`                                                | Formatting only; no new asset                                                                                              |
| `tls.Config.Clone`, `tls.Conn.Close`, `tls.CurveID.String`                                        | Configuration copying, connection cleanup, and formatting; no new asset                                                    |
| `tls.CipherSuites/InsecureCipherSuites`                                                           | Capability listings, not configured or negotiated cipher suites                                                            |
| `tls.Conn.ConnectionState`                                                                        | State access; no runtime observation made by the source scanner                                                            |
| `x509.NewCertPool`, `x509.CertPool.Clone`                                                         | Empty-container allocation or copy; no new certificate discovered                                                          |
| `ssh.Conn.Close`                                                                                  | Connection cleanup; no new asset                                                                                           |
| `ssh.Channel.Read/Write`, `ssh.Client.NewSession`                                                 | Configured SSH protocol use; negotiated algorithms remain unknown                                                          |
| `ssh.Session.Shell`                                                                               | Configured SSH shell request; no remote execution by the scanner                                                           |
| `ssh.PublicKeys`                                                                                  | Public-key authentication configuration; signer details unknown                                                            |
| `ssh.InsecureIgnoreHostKey`                                                                       | Host-key-check callback configuration, not a policy verdict                                                                |
| `ssh.Channel.Close`, `ssh.Session.Wait`                                                           | Channel cleanup and command-wait lifecycle; no new asset                                                                   |
| `ssh.Session.StdinPipe/StdoutPipe/StderrPipe`                                                     | Stream accessors; no new asset                                                                                             |
| `rsa.PublicKey.Equal`                                                                             | Public-key identity comparison; no new asset                                                                               |
| `rsa.PublicKey.Size`, `ecdsa.PublicKey.Equal`, `ed25519.PublicKey.Equal`, `mldsa.PublicKey.Equal` | Key metadata/identity checks; no new asset                                                                                 |
| `subtle.ConstantTimeCompare`, `hmac.Equal`                                                        | Constant-time comparison; not a standalone cryptographic asset or proof of a particular MAC algorithm                      |

The exact `cryptobyte.NewBuilder`, `Builder.AddUint16LengthPrefixed`,
`Builder.AddBytes`, `Builder.AddUint32`, `Builder.Bytes`, and
`String.ReadUint16LengthPrefixed` APIs are byte-encoding/decoding helpers, not
cryptographic operations. This is not blanket suppression of the package or
of similarly named methods on other types.

## Interface operations

`crypto.Signer.Sign` and `crypto.Decrypter.Decrypt` record configured signing and
public-key decryption intent. An opaque interface does not establish an algorithm,
key size, signature scheme, implementation backend, or successful operation.

`cipher.Block.Encrypt/Decrypt` can recover AES, DES, or 3DES and input key length
from visible constructors. Aliases, interface wrapping, and agreeing branches are
supported. Different key lengths remain unresolved; conflicting algorithms and
opaque factories remain generic block-cipher operations.

`cipher.Stream.XORKeyStream` follows visible CTR, OFB, and CFB constructors and
their block-cipher inputs. CTR/OFB do not establish an encryption versus
decryption direction. Explicit CFB encrypter/decrypter constructors do. Arbitrary
streams retain operation evidence without a guessed algorithm or direction.
Input key lengths are not security-strength claims.

## Resolution and source scope

Constructor tracking is bounded to visible calls, aliases/interface wrapping,
first-result extraction, and agreeing branches. It does not execute factories
or trace arbitrary wrappers, fields, or runtime mutations. For example, a
visible `NewGCM` can establish an AEAD operation's mode without assuming AES,
and a visible `NewCBCDecrypter` establishes decryption rather than encryption.
Conflicting constructors and opaque interfaces remain unresolved.

ML-DSA selectors supply the native `ML-DSA` family, parameter-set identifiers
`44`, `65`, or `87`, and their registered OIDs. Those identifiers are not key
lengths or inferred security scores. An unresolved `mldsa.GenerateKey` parameter
still records key-generation intent without choosing a parameter set. NaCl
secretbox sizes come from its fixed array-typed API; private bytes, nonce
uniqueness, successful authentication, and operation success are not established.

Static-analysis boundaries are documented here rather than repeated as generic
scope boilerplate in every CBOM or scanned module. Unknown parameters remain
internal analysis facts; their values and per-parameter unresolved lists are
omitted from the CBOM rather than replaced with placeholders. There is no
blanket suppression for methods named `String`, `Close`, `Public`, or `Verify`.

Parameter resolution includes integer constants, supported arithmetic, fixed
byte-array/slice lengths, equal-valued branches, and bounded propagation through
unexported non-escaping local functions. Exported parameters, ambiguous callers,
opaque interfaces, unsupported flows, and dynamic values remain unknown.
For RSA generation through receiver fields, explicit integer field initializers
are recorded as qualified alternatives rather than unconditional key sizes.
They are matched by field/type identity and retain their source locations.
For example, a factory assigning 4096 bits adds
`cadi:key-size-bits:declared = 4096` and a `field-initializer` parameter
fact, without setting an unconditional native parameter set on an unconstrained
method. Zero-value receivers, later mutation, other constructions, and whether
the factory is ever called are not proven away.
Mode constructors, AEAD calls, and `BlockMode` operations do not currently resolve
their underlying block cipher. The `Block` and `Stream` models described above
only resolve bounded visible constructors.
TLS struct initializers record explicit minimum/maximum versions, client-auth
mode, and peer-verification configuration; subsequent mutations and implicit
runtime defaults are not evaluated.

All selected packages and functions are inventoried, including functions that
may never execute. Enumeration follows source declarations, including methods
on unexported types, generic receiver methods, initializers, and nested closures;
it does not require a local caller. Generic bodies contribute one source site
regardless of how many type instantiations use them.
This is not a whole-program reachability proof. `_test.go`
files, `testdata`, `vendor`, hidden directories, and `node_modules` are excluded;
ordinary source packages used only by tests are not automatically classified.
Standalone test harnesses containing ordinary Go files remain in scope unless
explicitly excluded, even when their directory is named `test` or `tests`.

## Declarative certificate configuration

Cryptography can be requested without directly calling `crypto/x509`.
CADI recognizes resolved cert-manager `CertificateSpec` and
`CertificatePrivateKey` types in Go source, including aliases. Unrelated types
with the same short names are not treated as certificates.

These declarations produce configured certificate/key/algorithm assets linked
to their owning module and the resolved cert-manager API provider. Supported
settings include the requested key algorithm and size, encoding, rotation
policy, usages, and CA flag. Deployment-oriented common/DNS names, issuer and
Secret references, certificate lifetime, and renewal settings are not collected
from these specs. Certificate/key/algorithm findings and native relationships
remain; this does not remove subject, issuer, or validity details parsed from
actual certificates.

Constant fields and bounded, unambiguous initializer/copy patterns are resolved,
including private-key struct copies and usage lists. The resolver
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
Absent initializer fields and values that cannot be resolved are omitted from
the report, without exporting unresolved-field lists. Resolved declared
values have no companion `unknown` property. Literal values such as `false`, `0`,
and the string `"unknown"` remain ordinary known values.

Declaration evidence does not prove that a certificate was issued, deployed, or
used; actual serial numbers, validity timestamps, and fingerprints require
artifact or runtime evidence.

Source exclusions apply to these declarations too. A reusable key configuration
may have its own declaration evidence as well as evidence at a certificate
specification that uses it; neither entry represents an observed private key.

## Dependency preparation and read-only analysis

Source scans automatically prepare missing dependencies by default. Each
selected module is first checked against the local cache. If modules or
checksums are missing, CADI prepares the selected packages using the
existing Go proxy, private-module, checksum-service, and VCS authentication
settings, then retries source analysis offline.

Package discovery, dependency preparation, and typed loading share the selected
build flags, including `--tags`, and the requested `--goos`/`--goarch` environment.
Tagged dependencies are prepared for that same context; users do not need to
repeat CLI tags in `GOFLAGS`. Isolated-manifest flags are preserved throughout.

```sh
./bin/cadi scan /path/to/repository --output cbom.json
```

Standalone modules use isolated alternate `go.mod`/`go.sum` files for dependency
preparation. Workspaces use an isolated `go.work`/`go.work.sum` and read-only
manifest overlays; package-aware preparation honors local workspace members.
Workspace membership is checked per selected module, including normalized
absolute paths and symlink aliases. A discovered module not listed in the
workspace's `use` directives is analyzed independently with `GOWORK=off` in its
isolated subprocess, even when it sits beneath a listed module. Members continue
to use the workspace and its local-module resolution; the scanner neither edits
`go.work` to add omitted modules nor disables the workspace globally.
The scan report's per-module `module-context` details record the relative module
path and whether workspace mode was used. This selection happens before package
loading, not as a fallback that could hide genuine compilation errors.

A workspace's `go` directive must be at least as new as those in all member
`go.mod` files. CADI reports an older workspace directive separately from an
insufficient local toolchain; fix the workspace through its normal Go workflow.

Preparation does not run `go mod download all`, which can request unused
transitive versions and placeholders unrelated to the selected packages.
Local replacements continue to resolve against their original directories.
The target's manifests and checksum files are not modified. Preparation stops
rather than silently changing module requirements. It does not run tests,
`go generate`, or the target application.

Configure `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, and authentication as for a normal
Go build before scanning private repositories. CADI preserves these
settings during preparation; it does not invent credentials or upload source
to a scanning service. Go/VCS interactive password prompts and automatic Go
toolchain downloads are disabled. Preparation is bounded to ten minutes per
attempt and respects cancellation.

Use `--offline` for strict cache-only operation:

```sh
./bin/cadi scan /path/to/repository --offline --output cbom.json
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
./bin/cadi scan /path/to/repository \
  --goos linux --goarch amd64 --output cbom.json
```

If preparation or loading fails, the report remains incomplete and the command
exits 1. Invalid module versions, unavailable private credentials, checksum
failures, and incompatible local toolchains still require correction; they are
not converted into empty successful scans.

For package-load problems, CADI groups failures by safe cause and reports
the affected package count and an example location, instead of repeating a
numeric error kind for every import. For example, `module lookup disabled by
GOPROXY=off` means the offline cache is missing a required module version, not
that the cryptographic analyzer rejected an algorithm. Checksum, module-metadata,
syntax, and type-checking failures are reported separately.

The complete list of affected packages, positions, module directories, cause
categories, and preparation hints is retained in the scan report's
`package-load-errors` detail. Arbitrary compiler messages are not copied
into reports because they can contain source literals or credential-bearing
URLs. Unclassified failures direct you to the module's normal Go build/list
diagnostics. Scan-report details record `dependency-mode`,
`dependency-preparation`, and the structured Go `build-context`. Preparation
metadata does not include credentials or proxy URLs.

Loading packages can invoke the local Go compiler and native build tools to
obtain export information, but does not run tests, `go generate`, or the target
application. The analysis phase disables module network lookups and uses
`-mod=readonly`; source is not uploaded as a fallback.
