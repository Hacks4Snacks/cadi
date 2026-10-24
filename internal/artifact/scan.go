// Package artifact inventories explicit local artifacts without executing them.
package artifact

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"ciphertrail/internal/inventory"
	"ciphertrail/internal/material"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// MaxAssetBytes bounds in-memory parsing; local Go binaries use random-access reads.
const MaxAssetBytes int64 = 256 << 20

// Files inventories supported cryptographic files and Go executables.
type Files struct{ Path string }

// Collect scans an explicit file or directory without following symbolic links.
func (f Files) Collect(ctx context.Context) (inventory.Result, error) {
	var result inventory.Result
	root, err := filepath.Abs(f.Path)
	if err != nil {
		return result, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return result, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return result, fmt.Errorf("explicit artifact input is a symlink; supply its intended target directly")
	}
	if !info.IsDir() {
		found, err := inspectFile(ctx, &result, root, inventory.Evidence{Kind: "present", Collector: "file", Location: root}, true)
		if err == nil && !found {
			err = fmt.Errorf("no supported cryptographic material or Go build information in %s", root)
		}
		return result, err
	}
	var failures error
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			failures = errors.Join(failures, err)
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		location, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: location, Message: "symlink not followed"})
			return nil
		}
		if !entry.Type().IsRegular() {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: location, Message: "non-regular file not read"})
			return nil
		}
		_, err = inspectFile(ctx, &result, path, inventory.Evidence{Kind: "present", Collector: "file", Location: filepath.ToSlash(location)}, false)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", location, err))
		}
		return nil
	})
	if len(result.Entries) == 0 && failures == nil && err == nil {
		result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
			Location: root, Message: "no supported cryptographic assets or Go binaries found in the inspected files",
		})
	}
	return result, errors.Join(failures, err)
}

func inspectFile(ctx context.Context, result *inventory.Result, path string, evidence inventory.Evidence, explicit bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("artifact is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	prefix := make([]byte, 4)
	n, err := file.ReadAt(prefix, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if binaryMagic(prefix[:n]) {
		info, err := buildinfo.Read(file)
		if err != nil {
			if explicit {
				return false, fmt.Errorf("binary has no readable Go build information: %w", err)
			}
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: evidence.Location, Message: "native binary not analyzed: no Go build information"})
			return false, nil
		}
		addBuildInfo(result, info, evidence, "")
		return true, nil
	}
	if !explicit && !materialCandidate(path) && !opensslCandidate(path) {
		return false, nil
	}
	if info.Size() > MaxAssetBytes {
		return false, fmt.Errorf("asset exceeds the %d-byte parsing limit", MaxAssetBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxAssetBytes+1))
	if err != nil {
		return false, err
	}
	if int64(len(data)) > MaxAssetBytes {
		return false, fmt.Errorf("asset grew beyond the parsing limit")
	}
	return inspectBytes(result, data, evidence, "")
}

func inspectBytes(result *inventory.Result, data []byte, evidence inventory.Evidence, parent string) (bool, error) {
	if binaryMagic(data) {
		info, err := buildinfo.Read(bytes.NewReader(data))
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: evidence.Location, Message: "native binary not analyzed: no Go build information"})
			return false, nil
		}
		addBuildInfo(result, info, evidence, parent)
		return true, nil
	}
	if opensslCandidate(evidence.Location) {
		return parseOpenSSL(result, data, evidence, parent)
	}
	partial, recognized, err := material.Parse(data, evidence, parent)
	result.Merge(partial)
	if err == nil && !recognized && materialCandidate(evidence.Location) {
		err = fmt.Errorf("unrecognized cryptographic file format")
	}
	return recognized, err
}

func materialCandidate(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pem", ".crt", ".cer", ".der", ".key", ".pub":
		return true
	}
	switch filepath.Base(path) {
	case "authorized_keys", "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa":
		return true
	}
	return false
}

func binaryMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) ||
		string(data[:2]) == "MZ" ||
		bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(data[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
		bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xce})
}

func addBuildInfo(result *inventory.Result, info *debug.BuildInfo, evidence inventory.Evidence, parent string) {
	name := info.Path
	if name == "" {
		name = filepath.Base(evidence.Location)
	}
	component := cdx.Component{Type: "application", Name: name, Version: info.Main.Version}
	if info.Main.Path != "" {
		component.PackageURL = inventory.GoPURL(info.Main.Path, info.Main.Version)
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT", "-buildmode", "-compiler", "-tags", "vcs.revision", "vcs.modified", "vcs.time":
			inventory.Property(&component, "build."+setting.Key, setting.Value)
		}
	}
	binary := result.Add(component, evidence, parent)
	addDependency := func(component cdx.Component) {
		ref := result.Add(component, evidence, "")
		result.DependOn(binary, ref)
	}
	addDependency(cdx.Component{Type: "library", Name: "Go standard library", Version: info.GoVersion})
	for _, dependency := range info.Deps {
		path, version := dependency.Path, dependency.Version
		var replacement string
		if dependency.Replace != nil {
			replacement = dependency.Replace.Path
			version = dependency.Replace.Version
			if version != "" {
				path = dependency.Replace.Path
			}
		}
		module := cdx.Component{Type: "library", Name: path, Version: version, PackageURL: inventory.GoPURL(path, version)}
		if replacement != "" {
			inventory.Property(&module, "module-replacement", replacement)
		}
		addDependency(module)
	}
}
