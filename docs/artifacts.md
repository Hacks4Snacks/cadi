# Files and container images

[Home](../README.md) | [Scanning and exclusions](scanning.md) | [CBOM output](output.md)

Scan local files or the effective filesystem of a supported image without
running the target program or starting a container:

```sh
./bin/ciphertrail scan ./certificates ./service-binary --output artifacts.cbom.json
./bin/ciphertrail scan --image ./service-image.tar --output image.cbom.json
```

## Supported formats

Supported public metadata sources include:

- PEM/DER X.509 certificates and PKIX, PKCS#1, SEC1, and PKCS#8 keys.
- OpenSSH private keys and authorized/public-key entries, where supported by the
  Go SSH library.
- RSA, ECDSA, Ed25519, and supported ECDH public-key parameters.
- Encrypted private-key containers, recorded without guessed algorithm/size
  values and with an explicit no-decryption diagnostic rather than decrypted.
- Go executable build/module information. Linker flags and arbitrary build
  settings are excluded to avoid exporting embedded secrets.
- OpenSSL `.cnf` protocol, cipher-selector, group, and signature declarations.
  Includes, variables, selector expressions, and section activation are not
  evaluated.
- Supported [Kubernetes YAML/JSON declarations](kubernetes.md) and embedded TLS
  material, using the same detector as explicit manifest scans.

Go build information establishes dependency presence, not cryptographic use.
Use [`--include-dependencies`](output.md#crypto-focused-output) to export that
software inventory.

## Privacy and limits

File contents, private keys, passwords, and arbitrary source strings are not
included in reports. Key fingerprints are derived from public-key encodings only.
Reports still contain sensitive operational metadata such as paths, endpoint
names, certificate identities, and dependency versions; keep them internal.

Image collection respects whiteouts and opaque directories. It streams the
effective filesystem without extracting image paths to disk or following
links. Local artifact directory scans do not follow symlinks either, and report
those omissions. Supported images are single-image Docker save TARs and OCI
layout directories. OCI TAR archives, multi-image Docker TARs, registry pulls,
JKS/PKCS#12 stores, and general native-binary cryptographic disassembly are not
supported yet. Native binaries without Go build information are identified as
analysis limitations.

In-memory asset parsing is limited to 256 MiB per file. Oversized image assets
produce errors rather than silently disappearing. Local Go binaries use
random-access build-info reads rather than loading the whole executable.
