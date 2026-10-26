# TLS and SSH endpoint probes

[Home](../README.md) | [Scanning guide](scanning.md) | [CBOM output](output.md)

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

Probes cannot be combined with `--offline`. They collect observations, not an
exhaustive inventory of server capabilities.

## TLS and mutual TLS

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

## SSH

SSH verifies the host's key-exchange signature through the SSH implementation,
but does not establish known-host trust. The callback captures the public host
key and intentionally aborts before user authentication. An RSA key's
`ssh-rsa` encoding is **not** reported as evidence of a negotiated SHA-1
signature. SSH cipher/signature negotiation and server capability enumeration
are not inventoried.

## Observation limits

The probe's Go TLS/SSH negotiation defaults constrain what can be observed.
A failed handshake is a collection failure, not a cryptographic policy verdict.
There is no process attachment, eBPF instrumentation, Kubernetes discovery, or
automatic retrieval of cluster Secrets.
