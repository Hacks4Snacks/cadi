package scan

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"ciphertrail/internal/detect"
	"ciphertrail/internal/goscan"
	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/pyscan"
	"ciphertrail/internal/scope"
)

// Plan contains deduplicated work and every local input protected from output overwrite.
type Plan struct {
	Requests []Request
	Inputs   []string
}

type target struct {
	selection  scope.Selection
	err        error
	duplicates int
}

type pythonGroup struct {
	selection scope.Selection
	inputs    int
}

func (o Options) prepare(ctx context.Context, output string, selected []string) (Plan, error) {
	var plan Plan
	paths := slices.Clone(o.Paths)
	for i := range paths {
		paths[i] = canonical(paths[i])
	}
	slices.SortFunc(paths, func(a, b string) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(a, b)
	})
	paths = slices.Compact(paths)
	var targets []*target
	for _, path := range paths {
		plan.Inputs = append(plan.Inputs, path)
		selection, err := scope.Discover(ctx, path, scope.Options{
			Exclude: o.Exclude, IncludeNestedRepos: o.IncludeNestedRepos,
			Output:       canonicalOutput(output),
			ClassifyHelm: slices.Contains(selected, "kubernetes"),
			SkipReports:  slices.Contains(selected, "kubernetes") || slices.Contains(selected, "artifact"),
		})
		if selection.Target == "" {
			selection.Target = path
		}
		if selection.Root != "" {
			plan.Inputs = append(plan.Inputs, filepath.Join(selection.Root, ".ciphertrailignore"))
		}
		targets = append(targets, &target{selection: selection, err: err})
	}
	// An explicit file within a selected repository shares that repository's hard exclusions.
	for _, item := range targets {
		if item.selection.Directory || len(item.selection.Files) == 0 {
			continue
		}
		fileRoot := item.selection.Root
		for _, parent := range targets {
			if !parent.selection.Directory || !insidePath(parent.selection.Root, item.selection.Target) {
				continue
			}
			item.selection.Root = parent.selection.Root
			for _, omission := range parent.selection.Omissions {
				boundary := filepath.Join(parent.selection.Root, filepath.FromSlash(omission.Path))
				if omission.Reason == "nested-repository" && insidePath(boundary, item.selection.Target) {
					// Hard exclusions still apply, but project analysis must not
					// share mutation facts across a nested repository boundary.
					item.selection.Root = fileRoot
					break
				}
			}
			if scope.PathExcluded(parent.selection.Root, item.selection.Target, parent.selection.Exclusions) {
				item.selection.Files = nil
				item.selection.Omissions = append(item.selection.Omissions, scope.Omission{Path: relativePath(parent.selection.Root, item.selection.Target), Reason: "excluded"})
			}
			break
		}
	}
	type owner struct{ target, file int }
	files := map[string]owner{}
	for i, item := range targets {
		var retained []scope.File
		for _, file := range item.selection.Files {
			if prior, exists := files[file.Path]; exists {
				selectedFile := &targets[prior.target].selection.Files[prior.file]
				selectedFile.Explicit = selectedFile.Explicit || file.Explicit
				if selectedFile.Explicit {
					selectedFile.HelmTemplate = false
				}
				item.duplicates++
				continue
			}
			files[file.Path] = owner{i, len(retained)}
			retained = append(retained, file)
		}
		item.selection.Files = retained
	}
	var allFiles []scope.File
	moduleOwner := map[string]int{}
	for index, item := range targets {
		allFiles = append(allFiles, item.selection.Files...)
		for _, module := range item.selection.Modules {
			if _, exists := moduleOwner[module]; !exists {
				moduleOwner[module] = index
			}
		}
		item.selection.Modules = nil
	}
	eligible := map[string]bool{}
	for _, file := range allFiles {
		if !strings.HasSuffix(file.Path, ".go") || strings.HasSuffix(file.Path, "_test.go") {
			continue
		}
		for dir := filepath.Dir(file.Path); ; dir = filepath.Dir(dir) {
			if _, exists := moduleOwner[dir]; exists {
				eligible[dir] = true
				break
			}
			if filepath.Dir(dir) == dir {
				break
			}
		}
	}
	for module, index := range moduleOwner {
		if eligible[module] {
			targets[index].selection.Modules = append(targets[index].selection.Modules, module)
		}
	}
	pythonGroups := map[string]*pythonGroup{}
	if slices.Contains(selected, "python") {
		for _, item := range targets {
			if len(pyscan.Files(item.selection.Files)) == 0 {
				continue
			}
			root := item.selection.Root
			group := pythonGroups[root]
			if group == nil {
				group = &pythonGroup{selection: scope.Selection{Root: root, Target: root}}
				pythonGroups[root] = group
			}
			group.selection.Files = append(group.selection.Files, item.selection.Files...)
			group.inputs++
		}
	}
	for _, item := range targets {
		selection := item.selection
		slices.Sort(selection.Modules)
		var metadata inventory.Result
		scopeInfo := struct {
			Exclusions []string         `json:"exclusions,omitempty"`
			Omissions  []scope.Omission `json:"omissions,omitempty"`
			Charts     []string         `json:"helmCharts,omitempty"`
			Duplicates int              `json:"deduplicatedFiles,omitempty"`
		}{selection.Exclusions, selection.Omissions, selection.Charts, item.duplicates}
		encoded, err := json.Marshal(scopeInfo)
		if err != nil {
			return Plan{}, err
		}
		metadata.Metadata("scope", string(encoded))
		var collectors []inventory.Collector
		if slices.Contains(selected, "go") {
			if len(selection.Modules) > 0 {
				goSelection := selection
				goSelection.Files = allFiles
				collectors = append(collectors, goscan.Source{
					Path: selection.Root, Selection: &goSelection, GOOS: o.GOOS, GOARCH: o.GOARCH,
					Tags: o.Tags, Offline: o.Offline, IncludeNestedRepos: o.IncludeNestedRepos,
				})
			} else {
				status, reason := "not-applicable", "no Go modules with selected source"
				if item.duplicates > 0 && len(selection.Files) == 0 {
					status, reason = "deduplicated", "covered by another input"
				}
				metadata.Coverage = append(metadata.Coverage, inventory.Coverage{Analyzer: "go", Status: status, Reason: reason})
			}
		}
		fileSelection := selection
		if slices.Contains(selected, "python") {
			group := pythonGroups[selection.Root]
			if group != nil && group.inputs > 1 && len(pyscan.Files(selection.Files)) > 0 {
				metadata.Metadata("python-analysis-target", selection.Root)
				metadata.Coverage = append(metadata.Coverage, inventory.Coverage{
					Analyzer: "python", Status: "deduplicated", Reason: "shared Python analysis at " + selection.Root,
				})
			} else if item.duplicates > 0 && len(selection.Files) == 0 {
				metadata.Coverage = append(metadata.Coverage, inventory.Coverage{Analyzer: "python", Status: "deduplicated", Reason: "covered by another input"})
			} else {
				collectors = append(collectors, pyscan.Source{Selection: selection})
			}
			fileSelection.Files = slices.Clone(selection.Files)
			for index, file := range fileSelection.Files {
				if file.Explicit && strings.HasSuffix(file.Path, ".py") {
					// Source ownership does not require an unrelated artifact match.
					fileSelection.Files[index].Explicit = false
				}
			}
		}
		detectors, fallback := fileDetectors(selected)
		if len(detectors) > 0 {
			if len(selection.Files) > 0 {
				collectors = append(collectors, detect.Collector{
					Source: input.Local{Selection: &fileSelection}, Detectors: detectors, Fallback: fallback,
				})
			} else {
				for _, detector := range detectors {
					status, reason := "not-applicable", "no files selected"
					if item.duplicates > 0 {
						status, reason = "deduplicated", "covered by another input"
					}
					metadata.Coverage = append(metadata.Coverage, inventory.Coverage{Analyzer: detector.Name(), Status: status, Reason: reason})
				}
			}
		}
		name := "file"
		if selection.Directory {
			name = "repository"
		}
		plan.Requests = append(plan.Requests, Request{Name: name, Target: selection.Target,
			Collector: composed{metadata: metadata, collectors: collectors, initialError: item.err}})
	}
	var pythonRoots []string
	for root, group := range pythonGroups {
		if group.inputs > 1 {
			pythonRoots = append(pythonRoots, root)
		}
	}
	slices.Sort(pythonRoots)
	for _, root := range pythonRoots {
		plan.Requests = append(plan.Requests, Request{
			Name: "python", Target: root, Collector: pyscan.Source{Selection: pythonGroups[root].selection},
		})
	}
	plan.Requests = append(plan.Requests, o.additionalRequests(selected)...)
	plan.Inputs = append(plan.Inputs, o.Images...)
	for _, path := range []string{o.CAFile, o.ClientCert, o.ClientKey} {
		if path != "" {
			plan.Inputs = append(plan.Inputs, path)
		}
	}
	return plan, nil
}

type composed struct {
	metadata     inventory.Result
	collectors   []inventory.Collector
	initialError error
}

func (c composed) Collect(ctx context.Context) (inventory.Result, error) {
	result, failures := c.metadata, c.initialError
	for _, collector := range c.collectors {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(failures, err)
		}
		partial, err := collector.Collect(ctx)
		result.Merge(partial)
		failures = errors.Join(failures, err)
	}
	return result, failures
}

func imageRequest(path string, detectors []detect.Detector, selected []string) Request {
	var metadata inventory.Result
	if slices.Contains(selected, "python") {
		metadata.Coverage = append(metadata.Coverage, inventory.Coverage{Analyzer: "python", Status: "not-applicable", Reason: "Python source analysis requires local source paths; image interpreters are never executed"})
	}
	if slices.Contains(selected, "go") {
		metadata.Coverage = append(metadata.Coverage, inventory.Coverage{Analyzer: "go", Status: "not-applicable", Reason: "Go source analysis requires a directory; binaries use artifact analysis"})
	}
	var collectors []inventory.Collector
	if len(detectors) > 0 {
		collectors = append(collectors, detect.Collector{Source: input.Image{Path: path}, Detectors: detectors})
	}
	return Request{"image", path, composed{metadata: metadata, collectors: collectors}}
}

func canonicalOutput(path string) string {
	if path == "" || path == "-" {
		return ""
	}
	return canonical(path)
}

func insidePath(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && filepath.IsLocal(relative)
}

func relativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(relative)
}
