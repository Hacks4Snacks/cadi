// Package scope defines consistent, read-only repository selection for passive analyzers.
package scope

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Options controls repository scope, independently of analyzer selection.
type Options struct {
	Exclude            []string
	IncludeNestedRepos bool
	Outputs            []string
	ClassifyHelm       bool
	SkipReports        bool
}

func exclusionPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\*?[]!:\x00\r\n") {
		return "", errors.New("expected a literal root-relative file or directory path; globs, negation, and absolute paths are not supported")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return "", errors.New("exclusion must not traverse outside its root")
		}
	}
	value = path.Clean(value)
	if value == "." {
		return "", errors.New("exclusion must name a file or directory beneath the root")
	}
	return value, nil
}

// ValidateExclusions checks command-line scope syntax without filesystem access.
func ValidateExclusions(values []string) error {
	for _, value := range values {
		if _, err := exclusionPath(value); err != nil {
			return fmt.Errorf("invalid --exclude: %w", err)
		}
	}
	return nil
}

// LoadExclusions combines literal root-relative CLI and .ciphertrailignore entries.
func LoadExclusions(root string, specified []string) ([]string, error) {
	var exclusions []string
	add := func(value string) error {
		normalized, err := exclusionPath(value)
		if err != nil {
			return err
		}
		exclusions = append(exclusions, normalized)
		return nil
	}
	for _, value := range specified {
		if err := add(value); err != nil {
			return nil, fmt.Errorf("invalid --exclude: %w", err)
		}
	}
	const name = ".ciphertrailignore"
	info, err := os.Lstat(filepath.Join(root, name))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect %s: %w", name, err)
	}
	if err == nil {
		const limit = 64 << 10
		if !info.Mode().IsRegular() || info.Size() > limit {
			return nil, fmt.Errorf("%s must be a regular, non-symlink file no larger than 64 KiB", name)
		}
		file, err := os.OpenInRoot(root, name)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", name, err)
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if len(data) > limit {
			return nil, fmt.Errorf("%s exceeded 64 KiB while reading", name)
		}
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if err := add(line); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, i+1, err)
			}
		}
	}
	slices.Sort(exclusions)
	return slices.Compact(exclusions), nil
}

// PathExcluded matches a literal path or its descendants inside a root.
func PathExcluded(root, filename string, exclusions []string) bool {
	name, err := filepath.Rel(root, filename)
	if err != nil || !filepath.IsLocal(name) {
		return false
	}
	name = filepath.ToSlash(name)
	for _, exclusion := range exclusions {
		if name == exclusion || strings.HasPrefix(name, exclusion+"/") {
			return true
		}
	}
	return false
}

// DefaultDirectory identifies generated output, fixtures, dependencies, and hidden metadata.
func DefaultDirectory(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "vendor", "node_modules", "testdata", "test", "tests", "mocks", "samples", "examples",
		"bin", "out", "dist", "build", "target", "coverage", "__pycache__":
		return true
	}
	return false
}
