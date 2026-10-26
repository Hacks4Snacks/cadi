# Python source analysis

[Home](../README.md) | [Scanning and exclusions](scanning.md) | [CBOM output](output.md)

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

## API coverage

- Standard library: common `hashlib` hashes, named hash selection, PBKDF2/scrypt,
  HMAC, `secrets`, and `os.urandom`.
- `ssl`: context creation, wrapping APIs, declared TLS minima/maxima, verification
  settings, OpenSSL cipher selectors, and certificate/key/CA file references.
  These are configured settings, not negotiated versions or cipher suites.
- `cryptography`: common hash/HMAC and CMAC APIs; RSA, EC, Ed25519/Ed448, and
  X25519/X448 key generation; supported signature and key-agreement operations;
  AES and common block modes, key wrapping, AEAD, and Fernet;
  PBKDF2/HKDF/scrypt/Argon2; X.509 imports and certificate/CSR builder signing;
  and private/public key imports.
- `bcrypt`: password hashing/verification and bcrypt-PBKDF.
- `argon2`: `PasswordHasher` configuration, hashing, and verification.
- `Crypto` and `Cryptodome`: common hash/HMAC constructors, AES configuration
  and encryption/decryption entry points, RSA/ECC generation, and random bytes.
- HTTP clients: selected Requests, HTTPX, urllib3, and standard-library request
  APIs with an established HTTPS scheme.

Coverage is an explicit API model set, not complete coverage of those libraries.
Resolved but unmodeled crypto APIs produce file/line diagnostics. Known metadata
and lifecycle calls are classified by exact symbol rather than broad method-name
suppression. Algorithms are not inferred from arbitrary function names.

## Key agreement, wrapping, and CMAC

X25519/X448 private-key `exchange` calls record key-agreement intent with the
API's curve identity. EC `exchange` records ECDH when its selector is explicit,
and retains a curve only when a visible key-generation/derivation constructor
establishes it. An opaque selector remains generic elliptic-curve key agreement.
No shared-secret bytes, peer key contents, or successful handshake are inferred.

The four `keywrap.aes_key_wrap/unwrap` APIs, including their `_with_padding`
variants, use the native `key-wrap` primitive. AES-KW and AES-KWP have distinct
names and registered OIDs. Key size describes the wrapping key, not the wrapped
payload. Unknown or mutable key lengths do not receive a guessed OID; KWP is
not labeled as PKCS#7 padding.

CMAC construction, `finalize`, and `verify` retain tag-generation or verification
intent. Visible block-cipher constructors can establish the underlying algorithm
and key length; stream ciphers and opaque algorithms do not establish CMAC
parameters. `copy` preserves visible constructor context, while `update` and
`copy` do not create standalone cryptographic operations.

## Password hashing and KDFs

- `bcrypt.hashpw` records explicitly supplied `gensalt(rounds=...)` cost.
  `gensalt` alone is not a password-hashing finding, and its default cost is not
  assumed. `checkpw` records verification without decoding the stored hash.
- `bcrypt.kdf` is bcrypt-PBKDF: its linear `rounds` and requested output length
  are distinct from the logarithmic password-hashing cost.
- `argon2.PasswordHasher` and `hash` retain explicit variant, iteration count,
  memory cost in KiB, parallelism, and requested hash/salt lengths. Omitted
  version-dependent defaults stay unspecified. A per-call salt overrides the
  configured salt length; an unknown or expanded override keeps that length
  unresolved.
- `PasswordHasher.verify` selects parameters from the encoded hash. It does
  **not** inherit the hasher's configured variant or cost settings.
  `check_needs_rehash` is metadata comparison, not a cryptographic operation.
- `cryptography`'s `Argon2id`, `Argon2i`, and `Argon2d` constructors and
  `derive/verify` calls retain explicit keyword-only parameters. Known output
  lengths can feed subsequent modeled cipher constructors.

Argon2 variants have no invented `algorithmFamily` value when the CycloneDX
registry lacks one. Passwords, encoded hashes, keys, salts, and messages are not
exported or hashed into identifiers. These models do not verify credentials or
assert that a requested operation is valid or succeeded.

## HTTP clients and URL schemes

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

## Resolution, evidence, and limits

Direct, `from`, and aliased imports are resolved with lexical binding checks.
Parameters, rebinding, wildcard imports, local provider-named modules, and
observed namespace or instance attribute mutations prevent unsupported
attribution. Provider shadow files are checked by filesystem metadata even when
their contents are excluded. Mutation facts from selected files also invalidate
nested parameter expressions, not just the outer API call.

Inputs contributing Python files under the same source root share one analysis
before findings are constructed. Explicit files use their containing directory
as the root, or the selected repository root when they belong to one. Nested Git
boundaries honored by discovery keep analysis separate. Only selected files
participate: grouping does not discover additional files or bypass exclusions.

When multiple inputs contribute distinct files to a shared analysis, their
scan-report metadata retains `python-analysis-target` pointing to a
`python` collection at that root. Participating inputs show `deduplicated`
Python coverage; inspected-file counts, findings, and any analysis failure are
reported once in the shared collection. Overlapping selections still parse each
physical file only once. Separate source roots do not share mutation facts.

Literal integer expressions, immutable byte lengths, simple aliases, and selected
constructor results can establish public parameters. These describe visible
source configuration, not a runtime guarantee. Opaque calls, mutable byte arrays,
dynamic lookup, arbitrary side effects, and cross-module value/wrapper tracing
remain outside this bounded analysis. Unresolved parameters are tracked internally
but are not exported as lists or unknown-value placeholders.

Every finding retains its Python source location, line, and resolved API symbol.
Provider links identify import namespaces, not installed distributions or
versions: in particular, `Crypto` does not uniquely identify PyCryptodome.
The frontend interpreter version is scan-report metadata, not the target runtime
version. Python dependency manifests and lockfiles are not an installed-package
inventory.

Keys, messages, passwords, inline certificate contents, and other raw argument
values are not exported or used to form private-derived identifiers. Only modeled
public fields and lengths are retained. Referenced certificate/key paths are
not opened, and certificate signing declarations are not issued certificates.

Parsing is bounded to 8 MiB per source file, 100,000 AST nodes, 32 expression
levels, 200,000 resolved value visits, 64 arguments per call, and a 16 MiB frontend
response. Each file has a 10-second frontend deadline and supports cancellation.
Expression-budget exhaustion is a typed truncation outcome, not ordinary
unsupported value flow: valid partial facts and mutation information from that
file are retained, but coverage is `failed`, the CBOM and scan report are
`incomplete`, the human summary is marked `INCOMPLETE`, and the CLI exits 1.
Ordinary unsupported expressions remain qualified unknowns without failing an
otherwise completed analysis.

Each shared Python analysis also has a 128 MiB aggregate retained-fact budget,
measured in frontend JSON response bytes, and a 10-minute frontend collection
deadline. The remaining aggregate byte allowance limits each subprocess's output
before decoding. On exhaustion, collection stops; already collected facts are
modeled together with their shared mutation information, unprocessed files are
counted as skipped, and the limit is reported as failed coverage. A file whose
response exceeds the remaining allowance is counted as both attempted and
skipped because it was inspected but its analysis was not retained.

These are collection budgets, not a process-RSS ceiling or an end-to-end scan
deadline. Decoded Go objects, the current interpreter, inventory construction,
and CBOM encoding/validation have additional costs. Interpreter startup remains
one isolated process per selected file; no target imports or worker pooling are
introduced. Caller cancellation also interrupts finding construction.

Syntax, source-encoding, interpreter, and resource-limit errors are operational
failures. Valid evidence remains in the partial CBOM, with detailed failed
coverage in the [scan report](scan-report.md) and stderr.
The host interpreter must understand the selected source syntax; Python 3.10 is
the frontend minimum, not a promise that it parses every newer Python release.
Stubs, notebooks, bytecode, Python embedded in YAML or shell, and source analysis
inside images are not included.
