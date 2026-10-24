package testutil

import (
	"archive/tar"
	"bytes"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Layer builds a deterministic, disposable image layer.
func Layer(t *testing.T, files map[string][]byte) v1.Layer {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	var paths []string
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		contents := files[path]
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
	layer, err := tarball.LayerFromReader(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

// ImageArchive saves a local single-image archive without using a Docker daemon.
func ImageArchive(t *testing.T, files map[string][]byte) string {
	t.Helper()
	image, err := mutate.AppendLayers(empty.Image, Layer(t, files))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(path, name.MustParseReference("example.test/fixture:latest"), image); err != nil {
		t.Fatal(err)
	}
	return path
}
