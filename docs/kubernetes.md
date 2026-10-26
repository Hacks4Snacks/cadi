# Kubernetes and rendered Helm manifests

[Home](../README.md) | [Scanning guide](scanning.md) | [Scan reports](scan-report.md)

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

## Supported resources

| Resource                                             | Inventory treatment                                                                  |
|------------------------------------------------------|--------------------------------------------------------------------------------------|
| `cert-manager.io/v1 Certificate`                     | Requested X.509/key configuration, algorithm/size, encoding, usages, and CA intent   |
| `v1 Secret`, type `kubernetes.io/tls`                | Public metadata parsed from `tls.crt` and `tls.key`; private bytes are never output  |
| `networking.k8s.io/v1 Ingress`                       | Explicit TLS entries and declared Secret references; no negotiated protocol claim    |
| `v1 List` and supported typed Lists                  | Each item analyzed with a compact owner label and JSON-pointer field location        |
| `v1 ConfigMap`                                       | Typed YAML/JSON and PEM inside `data` or base64 `binaryData`, with nested provenance |
| CAPI kubeadm resources, v1beta1/v1beta2              | TLS/CA settings and inline bootstrap file contents                                   |
| kubeadm configuration, v1beta3/v1beta4               | Explicit cluster/init/join TLS and certificate configuration                         |
| `apiserver.config.k8s.io/v1 EncryptionConfiguration` | Ordered encryption providers and declared key references                             |

Multi-document YAML and JSON resources are supported. Kubernetes objects require
`metadata.name`; configuration documents such as EncryptionConfiguration do not.
Runtime-substituted identities in embedded profiles and CAPI bootstrap resources
stay unresolved without suppressing known settings. An omitted namespace stays
unspecified rather than being assumed to be `default`. Absent configuration fields
do not receive invented defaults. Retained Secret references are declarations:
the detector does not look up their targets or prove they exist. Cert-manager
deployment/spec details are omitted as described in
[declarative certificate configuration](go.md#declarative-certificate-configuration);
issuer chains are not validated from declarations.

For TLS Secrets, `stringData` overrides the corresponding `data` field, matching
Kubernetes merge semantics. Base64 decoding and material parsing happen locally;
unrelated Secret keys and non-TLS Secret contents are not inspected. Embedded
certificates and keys are `present` evidence, not runtime observations. Missing
or templated TLS material stays unresolved; malformed material fails the
collection while preserving valid findings from other fields or documents.
The detector does not validate key/certificate pairing or Kubernetes admission.

## Render Helm separately

Render Helm charts separately in your existing build workflow, then supply the
rendered output. CipherTrail does not invoke Helm, fetch chart dependencies,
evaluate `lookup`, or reconstruct values files and rendering flags. Recognized
`# Source: chart/templates/file.yaml` comments are retained as origin metadata.
Unrendered resource identities/directives produce explicit scope notes;
unresolved template expressions in supported fields are omitted without
exporting per-field unresolved lists or suppressing other resolved fields.

## Embedded configuration and bootstrap profiles

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

## Evidence locations and parsing limits

Structured provenance includes:

- `context.document`: one-based YAML/JSON document number.
- `context.field`: a JSON pointer, including List item and TLS entry indices.
- `context.renderedFrom`: a recognized Helm source marker, when present.
- `context.contentLine`: the line inside decoded PEM content, when applicable.
- `context.embedded`: an ordered chain of inner document/field/line positions
  and declared virtual `file` paths.

Resource identities and unresolved identity/path lists are not repeated in
exported provenance. A compact resource owner label remains in the graph, without
separate API-version/kind/namespace properties. Source-locator context is retained
so embedded findings can still be traced to their containing files and fields.

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
coverage notes; unrelated embedded kinds are retained in scan-report details.
Neither is treated as discovered cryptography. This is configuration inventory,
not a Kubernetes validator, policy engine, or live-cluster scanner.
