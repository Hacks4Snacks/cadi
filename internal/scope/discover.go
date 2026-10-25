package scope

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// File records one selected physical file and its reporting location.
type File struct {
	Path, Location, Root string
	Explicit             bool
	HelmTemplate         bool
}

// Omission explains a scope exclusion without treating it as proof of no cryptography.
type Omission struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Selection is a discovery snapshot shared by project and file analyzers.
type Selection struct {
	Root, Target string
	Directory    bool
	Files        []File
	Modules      []string
	Charts       []string
	Exclusions   []string
	Omissions    []Omission
}

// Discover selects an explicit file or directory without following symbolic links.
func Discover(ctx context.Context, target string, options Options) (Selection, error) {
	var selection Selection
	if err := ctx.Err(); err != nil {
		return selection, err
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		return selection, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return selection, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return selection, fmt.Errorf("explicit input is a symlink; supply its intended target directly")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return selection, err
	}
	absolute = filepath.Join(parent, filepath.Base(absolute))
	selection.Target, selection.Directory = absolute, info.IsDir()
	selection.Root = absolute
	if !selection.Directory {
		selection.Root = filepath.Dir(absolute)
	}
	selection.Exclusions, err = LoadExclusions(selection.Root, options.Exclude)
	if err != nil {
		return selection, err
	}
	omit := func(path, reason string) {
		relative, _ := filepath.Rel(selection.Root, path)
		selection.Omissions = append(selection.Omissions, Omission{Path: filepath.ToSlash(relative), Reason: reason})
	}
	var failures error
	err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			failures = errors.Join(failures, walkErr)
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if PathExcluded(selection.Root, path, selection.Exclusions) || options.Output != "" && path == options.Output {
			omit(path, "excluded")
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if path != absolute && DefaultDirectory(entry.Name()) {
				omit(path, "default-directory")
				return filepath.SkipDir
			}
			if path != absolute {
				marker, err := os.Lstat(filepath.Join(path, "pyvenv.cfg"))
				if err == nil && !marker.IsDir() {
					omit(path, "python-virtual-environment")
					return filepath.SkipDir
				}
				if err != nil && !os.IsNotExist(err) {
					failures = errors.Join(failures, fmt.Errorf("inspect Python virtual environment boundary: %w", err))
					return filepath.SkipDir
				}
			}
			if path != absolute && !options.IncludeNestedRepos {
				_, err := os.Lstat(filepath.Join(path, ".git"))
				if err == nil {
					omit(path, "nested-repository")
					return filepath.SkipDir
				}
				if !os.IsNotExist(err) {
					failures = errors.Join(failures, fmt.Errorf("inspect nested repository boundary: %w", err))
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			omit(path, "link-or-special-file")
			return nil
		}
		if selection.Directory && (strings.HasPrefix(entry.Name(), ".") || reportName(entry.Name())) {
			omit(path, "metadata-or-generated-report")
			return nil
		}
		if options.SkipReports && strings.EqualFold(filepath.Ext(path), ".json") {
			report, err := generatedReport(selection.Root, path)
			if err != nil {
				failures = errors.Join(failures, err)
				return nil
			}
			if report {
				omit(path, "generated-report")
				return nil
			}
		}
		location := absolute
		if selection.Directory {
			location, err = filepath.Rel(absolute, path)
			if err != nil {
				return err
			}
			location = filepath.ToSlash(location)
		}
		selection.Files = append(selection.Files, File{Path: path, Location: location, Root: selection.Root, Explicit: !selection.Directory})
		if selection.Directory && entry.Name() == "go.mod" {
			selection.Modules = append(selection.Modules, filepath.Dir(path))
		}
		if options.ClassifyHelm && entry.Name() == "Chart.yaml" {
			chart, err := helmChart(selection.Root, path)
			if err != nil {
				failures = errors.Join(failures, err)
			} else if chart {
				selection.Charts = append(selection.Charts, filepath.Dir(path))
			}
		}
		return nil
	})
	for i := range selection.Files {
		file := &selection.Files[i]
		if file.Explicit {
			continue
		}
		for _, chart := range selection.Charts {
			if within(filepath.Join(chart, "templates"), file.Path) {
				file.HelmTemplate = true
				break
			}
		}
	}
	slices.Sort(selection.Modules)
	slices.Sort(selection.Charts)
	return selection, errors.Join(failures, err)
}

func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && filepath.IsLocal(relative)
}

func reportName(name string) bool {
	name = strings.ToLower(name)
	return name == "cbom.json" || name == "sbom.json" ||
		strings.HasSuffix(name, ".cbom.json") || strings.HasSuffix(name, "_cbom.json") ||
		strings.HasSuffix(name, ".sbom.json") || strings.HasSuffix(name, "_sbom.json")
}

func generatedReport(root, path string) (bool, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false, err
	}
	file, err := os.OpenInRoot(root, relative)
	if err != nil {
		return false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false, nil
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false, nil
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false, nil
		}
		switch key {
		case "bomFormat":
			var format string
			return json.Unmarshal(value, &format) == nil && format == "CycloneDX", nil
		case "spdxVersion":
			var version string
			return json.Unmarshal(value, &version) == nil && strings.HasPrefix(version, "SPDX-"), nil
		}
	}
	return false, nil
}

func helmChart(root, path string) (bool, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false, err
	}
	file, err := os.OpenInRoot(root, relative)
	if err != nil {
		return false, err
	}
	defer file.Close()
	var node yaml.Node
	if yaml.NewDecoder(io.LimitReader(file, 64<<10)).Decode(&node) != nil || len(node.Content) == 0 {
		return false, fmt.Errorf("invalid Helm chart metadata in %s", path)
	}
	mapping := node.Content[0]
	document := map[string]string{}
	if mapping.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			if mapping.Content[i].Kind == yaml.ScalarNode && mapping.Content[i+1].Kind == yaml.ScalarNode {
				document[mapping.Content[i].Value] = mapping.Content[i+1].Value
			}
		}
	}
	return (document["apiVersion"] == "v1" || document["apiVersion"] == "v2") &&
		document["name"] != "" && document["version"] != "", nil
}
