package artifact

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/inventory"
	"ciphertrail/internal/testutil"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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
	result, err := (Files{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := inventory.Encode([]inventory.Collection{{Result: result}})
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
		if _, err := (Files{Path: path}).Collect(context.Background()); err == nil {
			t.Fatal("invalid explicit asset accepted")
		}
	}
}

func TestGoBinaryMetadata(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Files{Path: path}).Collect(context.Background())
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
	if _, err := inventory.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func layer(t *testing.T, files map[string][]byte) v1.Layer {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for path, contents := range files {
		if err := writer.WriteHeader(&tar.Header{Name: path, Mode: 0600, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := tarball.LayerFromReader(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestImageWhiteoutsAndOCILayout(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	image, err := mutate.AppendLayers(empty.Image,
		layer(t, map[string][]byte{"old.crt": certificate, "dir/old.crt": certificate}),
		layer(t, map[string][]byte{".wh.old.crt": {}, "dir/.wh..wh..opq": {}, "dir/new.crt": certificate}))
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
		result, err := (Image{Path: path}).Collect(context.Background())
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
		if _, err := inventory.Encode([]inventory.Collection{{Result: result}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestImageRejectsTraversal(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	image, err := mutate.AppendLayers(empty.Image, layer(t, map[string][]byte{"../../outside.pem": certificate}))
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "bad-image.tar")
	if err := tarball.WriteToFile(archive, name.MustParseReference("example.test/fixture:latest"), image); err != nil {
		t.Fatal(err)
	}
	if _, err := (Image{Path: archive}).Collect(context.Background()); err == nil {
		t.Fatal("unsafe image path accepted")
	}
}
