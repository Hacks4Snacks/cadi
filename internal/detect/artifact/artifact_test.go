package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cadi/internal/detect"
	"cadi/internal/export/cyclonedx"
	"cadi/internal/input"
	"cadi/internal/inventory"
	"cadi/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestFileInventoryAndSymlinkBoundary(t *testing.T) {
	_, _, certificate, key := testutil.Identity(t)
	directory, outside := t.TempDir(), t.TempDir()
	for path, contents := range map[string][]byte{
		filepath.Join(directory, "cert.pem"):   certificate,
		filepath.Join(directory, "key.pem"):    key,
		filepath.Join(outside, "external.pem"): certificate,
	} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "external.pem"), filepath.Join(directory, "external.pem")); err != nil {
		t.Fatal(err)
	}
	result, err := (detect.Collector{Source: input.Local{Path: directory}, Detectors: []detect.Detector{Detector{}}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, key[35:75]) {
		t.Fatal("private bytes exported")
	}
	if len(result.Diagnostics) == 0 {
		t.Fatal("skipped symlink was not reported")
	}
	for _, entry := range result.Entries {
		if strings.HasSuffix(entry.Evidence.Location, "external.pem") {
			t.Fatal("symlink escaped scan scope")
		}
	}
}

func TestMalformedAndUnsupportedExplicitFilesFail(t *testing.T) {
	for _, contents := range []string{"-----BEGIN CERTIFICATE-----\ninvalid", "not a cryptographic asset"} {
		path := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := (detect.Collector{Source: input.Local{Path: path}, Detectors: []detect.Detector{Detector{}}}).Collect(context.Background()); err == nil {
			t.Fatal("invalid explicit asset accepted")
		}
	}
}

func TestGoBinaryMetadata(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (detect.Collector{Source: input.Local{Path: path}, Detectors: []detect.Detector{Detector{}}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		found = found || entry.Component.Name == "Go standard library" && entry.Component.Version != ""
	}
	if !found {
		t.Fatal("Go build metadata absent")
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if len(result.Subjects) != 1 || bom.Metadata.Component == nil ||
		bom.Metadata.Component.BOMRef != result.Subjects[0] || bom.Metadata.Component.Type != cdx.ComponentTypeApplication ||
		len(*bom.Components) != 0 {
		t.Fatal("explicit binary lost its subject or its metadata was mistaken for cryptographic use")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		file := input.NewFile(path, int64(len(contents)), bytes.NewReader(contents))
		file.Explicit = explicit
		file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: path}
		streamed, found, err := (Detector{}).Detect(context.Background(), file)
		if err != nil || !found {
			t.Fatalf("streamed binary metadata failed: %v", err)
		}
		if explicit && (len(streamed.Subjects) != 1 || streamed.Subjects[0] != result.Subjects[0]) ||
			!explicit && len(streamed.Subjects) != 0 {
			t.Fatal("binary subject depends on reader type or was inferred for an incidental file")
		}
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	file := input.NewFile("large-binary", input.MaxAssetBytes+1, reader)
	file.RandomAccess, file.Explicit = reader, true
	file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: "large-binary"}
	if _, found, err := (Detector{}).Detect(context.Background(), file); err != nil || !found {
		t.Fatalf("local binary metadata was forced through whole-file buffering: %v", err)
	}
}

func TestImageWhiteoutsAndOCILayout(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	image, err := mutate.AppendLayers(empty.Image,
		testutil.Layer(t, map[string][]byte{"old.crt": certificate, "dir/old.crt": certificate}),
		testutil.Layer(t, map[string][]byte{".wh.old.crt": {}, "dir/.wh..wh..opq": {}, "dir/new.crt": certificate}))
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(archive, name.MustParseReference("example.test/fixture:latest"), image); err != nil {
		t.Fatal(err)
	}
	ociPath := t.TempDir()
	oci, err := layout.Write(ociPath, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := oci.AppendImage(image); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{archive, ociPath} {
		result, err := (detect.Collector{Source: input.Image{Path: path}, Detectors: []detect.Detector{Detector{}}}).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range result.Entries {
			if strings.HasSuffix(entry.Evidence.Location, "old.crt") {
				t.Fatal("deleted image asset reported")
			}
			found = found || strings.HasSuffix(entry.Evidence.Location, "dir/new.crt")
		}
		if !found {
			t.Fatal("effective image asset missing")
		}
		data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
		if err != nil {
			t.Fatal(err)
		}
		var bom cdx.BOM
		if err := json.Unmarshal(data, &bom); err != nil {
			t.Fatal(err)
		}
		if len(result.Subjects) != 1 || bom.Metadata.Component == nil ||
			bom.Metadata.Component.BOMRef != result.Subjects[0] || bom.Metadata.Component.Type != cdx.ComponentTypeContainer {
			t.Fatal("single-image archive/layout lost its primary container")
		}
	}
}

func TestImageRejectsTraversal(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	image, err := mutate.AppendLayers(empty.Image, testutil.Layer(t, map[string][]byte{"../../outside.pem": certificate}))
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "bad-image.tar")
	if err := tarball.WriteToFile(archive, name.MustParseReference("example.test/fixture:latest"), image); err != nil {
		t.Fatal(err)
	}
	if _, err := (detect.Collector{Source: input.Image{Path: archive}, Detectors: []detect.Detector{Detector{}}}).Collect(context.Background()); err == nil {
		t.Fatal("unsafe image path accepted")
	}
}

func TestMultiImageLayoutHasNoInventedPrimarySubject(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	path := t.TempDir()
	oci, err := layout.Write(path, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"first.pem", "second.pem"} {
		image, err := mutate.AppendLayers(empty.Image, testutil.Layer(t, map[string][]byte{filename: certificate}))
		if err != nil {
			t.Fatal(err)
		}
		if err := oci.AppendImage(image); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (detect.Collector{Source: input.Image{Path: path}, Detectors: []detect.Detector{Detector{}}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if len(result.Subjects) != 2 || bom.Metadata.Component != nil {
		t.Fatal("multi-image input was mislabeled as one primary container")
	}
	containers, certificates := 0, 0
	for _, component := range *bom.Components {
		if component.Type == cdx.ComponentTypeContainer {
			containers++
		}
		if component.CryptoProperties != nil && component.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			certificates++
		}
	}
	if containers != 2 || certificates != 1 {
		t.Fatalf("subject tracking changed consolidation: containers=%d certificates=%d", containers, certificates)
	}
}
