package kubernetes

import (
	"bytes"
	"context"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"
)

func FuzzManifestProducesValidPartialInventory(f *testing.F) {
	for _, seed := range []string{
		certificateManifest,
		"--- {apiVersion: cert-manager.io/v1, kind: Certificate, metadata: {name: first}, spec: {}}\n--- {apiVersion: cert-manager.io/v1, kind: Certificate, metadata: {name: second}, spec: {}}\n",
		"%YAML 1.1\n---\n" + certificateManifest + "...\n",
		"apiVersion: v1\nkind: List\nitems: []\n",
		"apiVersion: v1\nkind: Secret\nmetadata: {name: public}\ntype: kubernetes.io/tls\ndata: {tls.crt: invalid}\n",
		"apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: public}\nspec: {privateKey: {algorithm: ECDSA, size: 256}}\n",
		"apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: public}\nspec: {tls: [{hosts: [example.test]}]}\n",
		encryptionManifest,
		`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"profile"},"data":{"profile.yaml":"apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: [secrets]\n  providers:\n  - aesgcm:\n      keys:\n      - name: primary\n        secret: PRIVATE_FUZZ_SENTINEL\n"}}`,
		`{"apiVersion":"controlplane.cluster.x-k8s.io/v1beta2","kind":"KubeadmControlPlane","metadata":{"name":"cp","namespace":"${NAMESPACE}"},"spec":{"kubeadmConfigSpec":{"clusterConfiguration":{"caCertificateValidityPeriodDays":730,"apiServer":{"extraArgs":[{"name":"tls-min-version","value":"VersionTLS12"}]}}}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32768 {
			t.Skip()
		}
		file := input.NewFile("fixture.yaml", int64(len(data)), bytes.NewReader(data))
		file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: "fixture.yaml"}
		result, _, err := (Detector{Strict: true}).Detect(context.Background(), file)
		if _, encodeErr := cyclonedx.Encode([]inventory.Collection{{Collector: "kubernetes", Result: result, Err: err}}); encodeErr != nil {
			t.Fatalf("detector returned an invalid inventory: %v", encodeErr)
		}
	})
}
