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
		"apiVersion: v1\nkind: List\nitems: []\n",
		"apiVersion: v1\nkind: Secret\nmetadata: {name: public}\ntype: kubernetes.io/tls\ndata: {tls.crt: invalid}\n",
		"apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: public}\nspec: {privateKey: {algorithm: ECDSA, size: 256}}\n",
		"apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: public}\nspec: {tls: [{hosts: [example.test]}]}\n",
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
