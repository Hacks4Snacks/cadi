package input

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Image reads a single-image Docker save archive or an OCI layout directory.
type Image struct{ Path string }

// Walk visits effective filesystems as streams; it never extracts image paths to disk.
func (i Image) Walk(ctx context.Context, visitFile func(*File) error) (inventory.Result, error) {
	var result inventory.Result
	if err := ctx.Err(); err != nil {
		return result, err
	}
	info, err := os.Lstat(i.Path)
	if err != nil {
		return result, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return result, fmt.Errorf("image input must not be a symlink")
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return result, fmt.Errorf("image archive must be a regular file")
		}
		image, err := tarball.ImageFromPath(i.Path, nil)
		if err != nil {
			return result, fmt.Errorf("read single-image Docker archive: %w", err)
		}
		return i.walkImage(ctx, image, visitFile)
	}
	oci, err := layout.FromPath(i.Path)
	if err != nil {
		return result, fmt.Errorf("read OCI layout: %w", err)
	}
	index, err := oci.ImageIndex()
	if err != nil {
		return result, err
	}
	seen := map[string]bool{}
	var visit func(v1.ImageIndex, int) error
	visit = func(index v1.ImageIndex, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 16 {
			return fmt.Errorf("OCI index nesting exceeds 16")
		}
		manifest, err := index.IndexManifest()
		if err != nil {
			return err
		}
		var failures error
		for _, descriptor := range manifest.Manifests {
			key := descriptor.Digest.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			switch descriptor.MediaType {
			case types.OCIImageIndex, types.DockerManifestList:
				child, err := index.ImageIndex(descriptor.Digest)
				if err == nil {
					err = visit(child, depth+1)
				}
				failures = errors.Join(failures, err)
			case types.OCIManifestSchema1, types.DockerManifestSchema2:
				image, err := index.Image(descriptor.Digest)
				if err == nil {
					partial, scanErr := i.walkImage(ctx, image, visitFile)
					result.Merge(partial)
					err = scanErr
				}
				failures = errors.Join(failures, err)
			default:
				failures = errors.Join(failures, fmt.Errorf("unsupported OCI descriptor type %s", descriptor.MediaType))
			}
		}
		return failures
	}
	err = visit(index, 0)
	if err == nil && len(result.Entries) == 0 {
		err = fmt.Errorf("OCI layout contains no supported images")
	}
	return result, err
}

func (i Image) walkImage(ctx context.Context, image v1.Image, visit func(*File) error) (inventory.Result, error) {
	var result inventory.Result
	digest, err := image.Digest()
	if err != nil {
		return result, err
	}
	config, err := image.ConfigFile()
	if err != nil {
		return result, err
	}
	location := filepath.Base(i.Path) + "@" + digest.String()
	evidence := inventory.Evidence{Kind: "present", Collector: "image", Location: location}
	component := cdx.Component{Type: "container", Name: filepath.Base(i.Path), Version: digest.String()}
	inventory.Property(&component, "os", config.OS)
	inventory.Property(&component, "architecture", config.Architecture)
	parent := result.Add(component, evidence, "")
	stream := mutate.Extract(image)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	reader := tar.NewReader(contextReader{ctx, stream})
	var failures error
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, errors.Join(failures, fmt.Errorf("read effective image filesystem: %w", err))
		}
		clean := path.Clean(header.Name)
		if path.IsAbs(header.Name) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(header.Name, "\\") {
			return result, fmt.Errorf("unsafe image entry path %q", header.Name)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
				result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: location + "!/" + clean, Message: "image link not followed"})
			}
			continue
		}
		file := NewFile(clean, header.Size, reader)
		file.Evidence, file.Parent = evidence, parent
		file.Evidence.Location = location + "!/" + clean
		err = visit(file)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", clean, err))
		}
	}
	// A tar terminator can precede the producer's pipe error.
	if _, err := io.Copy(io.Discard, contextReader{ctx, stream}); err != nil {
		failures = errors.Join(failures, fmt.Errorf("finish image extraction: %w", err))
	}
	return result, errors.Join(failures, ctx.Err())
}
