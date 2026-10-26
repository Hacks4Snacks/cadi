package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"cadi/internal/detect"
	"cadi/internal/goscan"
	"cadi/internal/input"
	"cadi/internal/inventory"
	"cadi/internal/pyscan"
	"cadi/internal/scope"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Plan contains deduplicated work and every local input protected from output overwrite.
type Plan struct {
	Requests []Request
	Inputs   []string
}

type target struct {
	selection   scope.Selection
	err         error
	duplicates  int
	projectRoot string
}

type pythonGroup struct {
	selection   scope.Selection
	inputs      int
	projectRoot string
}

func (o Options) prepare(ctx context.Context, outputs []string, selected []string) (Plan, error) {
	var plan Plan
	var excludedOutputs []string
	for _, output := range outputs {
		if path := canonicalOutput(output); path != "" {
			excludedOutputs = append(excludedOutputs, path)
		}
	}
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
			Outputs:      excludedOutputs,
			ClassifyHelm: slices.Contains(selected, "kubernetes"),
			SkipReports:  true,
		})
		if selection.Target == "" {
			selection.Target = path
		}
		if selection.Root != "" {
			plan.Inputs = append(plan.Inputs, filepath.Join(selection.Root, scope.IgnoreFileName))
		}
		targets = append(targets, &target{selection: selection, err: err})
	}
	assignProjectRoots(ctx, targets)
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
				if (omission.Reason == "nested-repository" || omission.Reason == "separate-project-root") &&
					insidePath(boundary, item.selection.Target) {
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
	moduleOwner := map[string]int{}
	for index, item := range targets {
		for _, module := range item.selection.Modules {
			if _, exists := moduleOwner[module]; !exists {
				moduleOwner[module] = index
			}
		}
		item.selection.Modules = nil
	}
	moduleFiles := map[string][]scope.File{}
	for _, item := range targets {
		for _, file := range item.selection.Files {
			if !strings.HasSuffix(file.Path, ".go") || strings.HasSuffix(file.Path, "_test.go") {
				continue
			}
			for dir := filepath.Dir(file.Path); ; dir = filepath.Dir(dir) {
				if owner, exists := moduleOwner[dir]; exists {
					if targets[owner].projectRoot == item.projectRoot {
						moduleFiles[dir] = append(moduleFiles[dir], file)
					}
					break
				}
				if filepath.Dir(dir) == dir {
					break
				}
			}
		}
	}
	for module, index := range moduleOwner {
		if len(moduleFiles[module]) > 0 {
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
				group = &pythonGroup{selection: scope.Selection{Root: root, Target: root}, projectRoot: item.projectRoot}
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
		metadata.Metadata("scope", scopeInfo)
		var collectors []inventory.Collector
		if slices.Contains(selected, "go") {
			if len(selection.Modules) > 0 {
				goSelection := selection
				goSelection.Files = nil
				for _, module := range selection.Modules {
					goSelection.Files = append(goSelection.Files, moduleFiles[module]...)
				}
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
			Collector: composed{metadata: metadata, collectors: collectors, initialError: item.err, projectRoot: item.projectRoot}})
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
			Name: "python", Target: root, Collector: composed{
				collectors:  []inventory.Collector{pyscan.Source{Selection: pythonGroups[root].selection}},
				projectRoot: pythonGroups[root].projectRoot,
			},
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

func assignProjectRoots(ctx context.Context, targets []*target) {
	for index, item := range targets {
		directory := item.selection.Target
		if item.selection.Directory {
			item.projectRoot = item.selection.Root
		} else {
			directory = filepath.Dir(directory)
		}
		for _, parent := range targets[:index] {
			if !parent.selection.Directory || !insidePath(parent.selection.Root, item.selection.Target) {
				continue
			}
			separate, err := crossesRepository(ctx, parent.selection.Root, directory)
			if err != nil {
				item.err = errors.Join(item.err, fmt.Errorf("inspect project boundary: %w", err))
				break
			}
			if !separate {
				item.projectRoot = parent.projectRoot
				break
			}
		}
	}
	// An explicitly selected independent repository owns its work even when an
	// ancestor's recursive discovery also included those files and modules.
	for _, item := range targets {
		if !item.selection.Directory {
			continue
		}
		for _, child := range targets {
			if !child.selection.Directory || child.projectRoot != child.selection.Root ||
				child.projectRoot == item.projectRoot || !insidePath(item.selection.Root, child.selection.Root) {
				continue
			}
			before := len(item.selection.Files) + len(item.selection.Modules)
			item.selection.Files = slices.DeleteFunc(item.selection.Files, func(file scope.File) bool {
				return insidePath(child.selection.Root, file.Path)
			})
			item.selection.Modules = slices.DeleteFunc(item.selection.Modules, func(module string) bool {
				return insidePath(child.selection.Root, module)
			})
			if before != len(item.selection.Files)+len(item.selection.Modules) {
				item.selection.Omissions = append(item.selection.Omissions, scope.Omission{
					Path: relativePath(item.selection.Root, child.selection.Root), Reason: "separate-project-root",
				})
			}
		}
	}
}

func crossesRepository(ctx context.Context, root, directory string) (bool, error) {
	for current := directory; current != root && insidePath(root, current); current = filepath.Dir(current) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	return false, nil
}

type composed struct {
	metadata     inventory.Result
	collectors   []inventory.Collector
	initialError error
	projectRoot  string
}

func (c composed) Collect(ctx context.Context) (result inventory.Result, failures error) {
	result, failures = c.metadata, c.initialError
	if c.projectRoot != "" {
		defer func() {
			failures = errors.Join(failures, addProjectSubject(&result, c.projectRoot))
		}()
	}
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

func addProjectSubject(result *inventory.Result, root string) error {
	subjects := map[string]bool{}
	refs := map[string]bool{}
	for _, entry := range result.Entries {
		refs[entry.Component.BOMRef] = true
	}
	for _, ref := range result.Subjects {
		if !refs[ref] {
			return fmt.Errorf("project context references missing collector subject %q", ref)
		}
		subjects[ref] = true
	}
	project := cdx.Component{
		BOMRef: inventory.Ref("source-project", root), Type: cdx.ComponentTypeApplication,
		Name: filepath.Base(root), Description: "Source project inventory for the selected directory root",
	}
	ref := result.Add(project, inventory.Evidence{Kind: "present", Collector: "repository", Location: "."}, "")
	for index := range result.Entries {
		entry := &result.Entries[index]
		if entry.Component.BOMRef == ref || entry.Parent != "" ||
			entry.Component.Type == cdx.ComponentTypeLibrary && !subjects[entry.Component.BOMRef] {
			continue
		}
		// IDs were assigned by the collectors; adding enclosing ownership must
		// not regenerate asset or occurrence identity.
		entry.Parent = ref
	}
	result.Subjects = []string{ref}
	result.Metadata("project-subject", ref)
	return nil
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
