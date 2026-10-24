// Package artifact detects public cryptographic material and binary/configuration metadata.
package artifact

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"fmt"
	"path/filepath"
	"runtime/debug"
	"strings"

	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/material"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Detector recognizes certificate/key files, OpenSSL configuration, and Go binaries.
type Detector struct{}

// Name identifies this built-in detector.
func (Detector) Name() string { return "artifact" }

// Match selects supported names, native executable headers, and PEM content.
func (Detector) Match(file *input.File, prefix []byte) bool {
	return materialCandidate(file.Name) || opensslCandidate(file.Name) || binaryMagic(prefix) ||
		bytes.HasPrefix(bytes.TrimSpace(prefix), []byte("-----BEGIN "))
}

// Detect inspects a file without executing it or exporting private material.
func (Detector) Detect(ctx context.Context, file *input.File) (inventory.Result, bool, error) {
	var result inventory.Result
	prefix, err := file.Prefix(ctx, 4)
	if err != nil {
		return result, false, err
	}
	if binaryMagic(prefix) && file.RandomAccess != nil {
		info, err := buildinfo.Read(file.RandomAccess)
		if err != nil {
			if file.Explicit {
				return result, false, fmt.Errorf("binary has no readable Go build information: %w", err)
			}
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: file.Evidence.Location, Message: "native binary not analyzed: no Go build information"})
			return result, false, nil
		}
		addBuildInfo(&result, info, file.Evidence, file.Parent)
		return result, true, nil
	}
	data, err := file.ReadAll(ctx, input.MaxAssetBytes)
	if err != nil {
		return result, false, err
	}
	found, err := inspectBytes(&result, data, file.Evidence, file.Parent)
	return result, found, err
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
		case "GOOS", "GOARCH", "CGO_ENABLED", "-buildmode", "-compiler", "GOEXPERIMENT", "-tags", "vcs.revision", "vcs.modified", "vcs.time":
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
