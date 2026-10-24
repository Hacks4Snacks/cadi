// Package goscan inventories Go cryptographic call sites in an explicit build context.
package goscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Source inventories source directories without running target code.
type Source struct {
	Path               string
	GOOS               string
	GOARCH             string
	Tags               string
	Exclude            []string
	IncludeNestedRepos bool
	Offline            bool
}

const analysisScope = "source evidence describes configured call sites and declarations, not runtime execution; only documented APIs and bounded value flows are modeled; material contents, issuance, operation success, negotiation, subsequent mutations, and implicit defaults are not established"

// Collect accounts for each discovered module and returns partial evidence with any load failure.
func (s Source) Collect(ctx context.Context) (inventory.Result, error) {
	result := inventory.Result{Properties: []cdx.Property{
		{Name: "ciphertrail:analysis-scope", Value: analysisScope},
		{Name: "ciphertrail:source-exclusions", Value: "test files; vendor; testdata; hidden directories; node_modules"},
	}}
	repositoryScope := "explicit-roots"
	if s.IncludeNestedRepos {
		repositoryScope = "recursive"
	}
	result.Properties = append(result.Properties, cdx.Property{Name: "ciphertrail:nested-repository-scope", Value: repositoryScope})
	dependencyMode := "automatic"
	if s.Offline {
		dependencyMode = "offline"
	}
	result.Properties = append(result.Properties, cdx.Property{Name: "ciphertrail:dependency-mode", Value: dependencyMode})
	if err := ctx.Err(); err != nil {
		return result, err
	}
	root, err := filepath.Abs(s.Path)
	if err != nil {
		return result, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return result, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return result, err
	}
	if !info.IsDir() {
		return result, fmt.Errorf("Go source input must be a directory")
	}
	exclusions, err := loadExclusions(root, s.Exclude)
	if err != nil {
		return result, err
	}
	if len(exclusions) > 0 {
		data, err := json.Marshal(exclusions)
		if err != nil {
			return result, fmt.Errorf("encode source exclusion scope: %w", err)
		}
		result.Properties = append(result.Properties, cdx.Property{Name: "ciphertrail:source-exclusion-paths", Value: string(data)})
	}
	var modules, nestedRepositories []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path != root && (sourcePathExcluded(root, path, exclusions) || entry.IsDir() && excluded(entry.Name())) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path != root && entry.IsDir() && !s.IncludeNestedRepos {
			_, markerErr := os.Lstat(filepath.Join(path, ".git"))
			if markerErr == nil {
				boundary := relative(root, path)
				nestedRepositories = append(nestedRepositories, boundary)
				exclusions = append(exclusions, boundary)
				return filepath.SkipDir
			}
			if !os.IsNotExist(markerErr) {
				return fmt.Errorf("inspect nested repository boundary: %w", markerErr)
			}
		}
		if !entry.IsDir() && entry.Name() == "go.mod" {
			modules = append(modules, filepath.Dir(path))
		}
		return nil
	})
	if len(nestedRepositories) > 0 {
		data, encodeErr := json.Marshal(nestedRepositories)
		if encodeErr != nil {
			return result, fmt.Errorf("encode repository boundary scope: %w", encodeErr)
		}
		result.Properties = append(result.Properties, cdx.Property{Name: "ciphertrail:excluded-nested-repositories", Value: string(data)})
	}
	if err != nil {
		return result, fmt.Errorf("discover Go modules: %w", err)
	}
	if len(modules) == 0 {
		if len(nestedRepositories) > 0 {
			return result, fmt.Errorf("no Go modules selected in %s; use explicit --source roots or --include-nested-repos for nested repositories", root)
		}
		return result, fmt.Errorf("no Go modules found in %s", root)
	}
	env := s.environment(true)
	command := exec.CommandContext(ctx, "go", "env", "-json", "GOOS", "GOARCH", "GOVERSION", "CGO_ENABLED", "GOEXPERIMENT")
	command.Dir, command.Env = root, env
	data, err := command.Output()
	if err != nil {
		return result, fmt.Errorf("read local Go build context: %w", err)
	}
	var build map[string]string
	if err := json.Unmarshal(data, &build); err != nil {
		return result, fmt.Errorf("decode Go build context: %w", err)
	}
	build["tags"] = s.Tags
	encodedBuild, err := json.Marshal(build)
	if err != nil {
		return result, err
	}
	result.Properties = append(result.Properties, cdx.Property{Name: "ciphertrail:build-context", Value: string(encodedBuild)})
	var failures error
	for _, module := range modules {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(failures, err)
		}
		partial, err := s.scanModule(ctx, root, module, env, string(encodedBuild), build["GOVERSION"], exclusions)
		result.Merge(partial)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", relative(root, module), err))
		}
	}
	return result, failures
}

func (s Source) scanModule(ctx context.Context, root, directory string, env []string, build, version string, exclusions []string) (result inventory.Result, returnErr error) {
	files, err := isolateModuleFiles(ctx, directory, env)
	if err != nil {
		return result, err
	}
	defer func() {
		if err := files.cleanup(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("clean isolated manifests: %w", err))
		}
	}()
	config := &packages.Config{
		Context: ctx, Dir: directory, Env: files.env,
		Mode:       packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedDeps | packages.NeedModule,
		BuildFlags: []string{"-mod=readonly"},
	}
	config.BuildFlags = append(config.BuildFlags, files.flags...)
	if s.Tags != "" {
		config.BuildFlags = append(config.BuildFlags, "-tags="+s.Tags)
	}
	prepared := false
	selectRoots := func(loaded []*packages.Package) []*packages.Package {
		return slices.DeleteFunc(loaded, func(pkg *packages.Package) bool {
			if len(pkg.GoFiles) == 0 {
				return false
			}
			for _, file := range pkg.GoFiles {
				if !sourcePathExcluded(root, file, exclusions) {
					return false
				}
			}
			return true
		})
	}
	load := func(patterns ...string) ([]*packages.Package, error) {
		loaded, err := packages.Load(config, patterns...)
		loaded = selectRoots(loaded)
		if prepared || !needsDependencyPreparation(loaded, err) {
			if err != nil && ctx.Err() == nil {
				err = fmt.Errorf("Go package loading: %s", safeGoFailure(err.Error()))
			}
			return loaded, err
		}
		prepared = true
		preparePatterns := patterns
		if len(loaded) > 0 {
			preparePatterns = make([]string, 0, len(loaded))
			for _, pkg := range loaded {
				preparePatterns = append(preparePatterns, pkg.PkgPath)
			}
		}
		preparationErr := files.prepare(ctx, directory, s.environment(s.Offline), preparePatterns)
		status := "prepared"
		if preparationErr != nil {
			status = "failed"
		}
		details, encodeErr := json.Marshal(struct {
			Module  string `json:"module"`
			Status  string `json:"status"`
			Offline bool   `json:"offline"`
		}{Module: relative(root, directory), Status: status, Offline: s.Offline})
		if encodeErr != nil {
			return nil, encodeErr
		}
		result.Properties = append(result.Properties, cdx.Property{Name: "ciphertrail:dependency-preparation", Value: string(details)})
		if preparationErr != nil {
			return loaded, preparationErr
		}
		loaded, err = packages.Load(config, patterns...)
		if err != nil && ctx.Err() == nil {
			err = fmt.Errorf("Go package loading after preparation: %s", safeGoFailure(err.Error()))
		}
		return selectRoots(loaded), err
	}
	metadata, err := load("./...")
	if err != nil {
		return result, fmt.Errorf("load Go dependency inventory: %w", err)
	}
	if len(metadata) == 0 {
		result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
			Location: relative(root, directory), Message: "no Go packages selected after source exclusions and build constraints",
		})
		return result, nil
	}
	parents := map[string]string{}
	moduleEntries := map[string]bool{}
	var loadErrors []loadProblem
	packages.Visit(metadata, nil, func(pkg *packages.Package) {
		var component cdx.Component
		if pkg.Module == nil {
			component = cdx.Component{Type: "library", Name: "Go standard library", Version: version}
		} else {
			component = moduleComponent(pkg.Module)
		}
		component.BOMRef = inventory.Ref("go-software", component.Name, component.Version, moduleIdentity(pkg.Module))
		if pkg.Module != nil && pkg.Module.Main {
			inventory.Property(&component, "build-context", build)
			inventory.Property(&component, "source-exclusions", "test files; vendor; testdata; hidden directories; node_modules")
			inventory.Property(&component, "analysis-scope", analysisScope)
		}
		evidence := inventory.Evidence{
			Kind: "present", Collector: "go", Location: relative(root, filepath.Join(directory, "go.mod")),
		}
		parents[pkg.PkgPath] = component.BOMRef
		if !moduleEntries[component.BOMRef] {
			result.Add(component, evidence, "")
			moduleEntries[component.BOMRef] = true
		}
		loadErrors = append(loadErrors, packageLoadProblems(pkg)...)
	})
	if err := reportLoadProblems(&result, relative(root, directory), loadErrors); err != nil {
		return result, err
	}
	seenEdges := map[[2]string]bool{}
	packages.Visit(metadata, nil, func(pkg *packages.Package) {
		for _, imported := range pkg.Imports {
			parent, child := parents[pkg.PkgPath], parents[imported.PkgPath]
			edge := [2]string{parent, child}
			if parent != "" && child != "" && parent != child && !seenEdges[edge] {
				result.DependOn(parent, child)
				seenEdges[edge] = true
			}
		}
	})
	config.Mode = packages.LoadSyntax | packages.NeedModule
	patterns := make([]string, 0, len(metadata))
	for _, pkg := range metadata {
		patterns = append(patterns, pkg.PkgPath)
	}
	loaded, err := load(patterns...)
	if err != nil {
		return result, fmt.Errorf("load typed Go syntax: %w", err)
	}
	if len(loaded) == 0 {
		result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: relative(root, directory), Message: "no Go packages match this build context"})
		return result, nil
	}
	packages.Visit(loaded, nil, func(pkg *packages.Package) {
		loadErrors = append(loadErrors, packageLoadProblems(pkg)...)
	})
	if err := reportLoadProblems(&result, relative(root, directory), loadErrors); err != nil {
		return result, err
	}
	program, initial := ssautil.Packages(loaded, ssa.InstantiateGenerics)
	program.Build()
	own := map[*ssa.Package]bool{}
	for _, pkg := range initial {
		if pkg != nil {
			own[pkg] = true
		}
	}
	var functions []*ssa.Function
	for function := range ssautil.AllFunctions(program) {
		if own[function.Pkg] && len(function.Blocks) > 0 {
			functions = append(functions, function)
		}
	}
	slices.SortFunc(functions, func(a, b *ssa.Function) int { return int(a.Pos()) - int(b.Pos()) })
	project := newDeclarationProject(root, loaded, exclusions)
	values := newValues(functions, project)
	for _, function := range functions {
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				call, ok := instruction.(ssa.CallInstruction)
				if !ok || call.Pos() == token.NoPos {
					continue
				}
				path, name, symbol := callSymbol(call.Common())
				if !cryptoPackage(path) {
					continue
				}
				if nonAssetAPI(calledAPI(call.Common())) {
					continue
				}
				position := program.Fset.PositionFor(call.Pos(), false)
				if !inside(root, position.Filename) || sourcePathExcluded(root, position.Filename, exclusions) {
					continue
				}
				evidence := inventory.Evidence{Kind: "configured", Collector: "go",
					Location: relative(root, position.Filename), Line: position.Line, Symbol: symbol}
				component, matched := recognize(path, name, call.Common(), values, &evidence)
				if matched {
					addConfiguredParameters(&component, &evidence, call.Common(), values)
					ref := result.Add(component, evidence, parents[function.Pkg.Pkg.Path()])
					result.DependOn(ref, parents[path])
				} else {
					result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
						Location: evidence.Location, Line: evidence.Line,
						Message: "cryptographic API not modeled: " + symbol,
					})
				}
			}
		}
	}
	for _, pkg := range loaded {
		scanCryptoDeclarations(&result, root, pkg, parents[pkg.PkgPath], parents, exclusions, project)
	}
	return result, ctx.Err()
}

type loadProblem struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Position string `json:"position,omitempty"`
	Kind     string `json:"kind"`
	Cause    string `json:"cause"`
	Hint     string `json:"hint"`
}

func packageLoadProblems(pkg *packages.Package) []loadProblem {
	problems := make([]loadProblem, 0, len(pkg.Errors))
	for _, issue := range pkg.Errors {
		problem := loadProblem{Package: pkg.PkgPath, Position: issue.Pos,
			Kind: "loading", Cause: "Go package loading failed",
			Hint: "inspect go list or build diagnostics in this module"}
		// Compiler messages may contain literal secrets or credential-bearing
		// URLs. Preserve safe causes and locations, not arbitrary source text.
		switch issue.Kind {
		case packages.ListError:
			problem.Kind = "dependency listing"
			switch {
			case strings.Contains(issue.Msg, "module lookup disabled by GOPROXY=off"):
				problem.Cause = "offline dependency cache miss: module lookup disabled by GOPROXY=off"
				problem.Hint = "run go mod download in this module using the repository's dependency settings, then rescan"
			case strings.Contains(issue.Msg, "missing go.sum entry"):
				problem.Cause = "missing module checksum"
				problem.Hint = "prepare this module's dependencies and checksums with its normal build workflow, then rescan"
			case strings.Contains(issue.Msg, "updates to go.mod needed"):
				problem.Cause = "module metadata requires updates; scanning is read-only"
				problem.Hint = "repair go.mod/go.sum with the repository's normal build workflow before scanning"
			case strings.Contains(issue.Msg, "no required module provides package"):
				problem.Cause = "no required module provides the imported package"
				problem.Hint = "check module declarations and replacements in this module before scanning"
			case strings.Contains(issue.Msg, "build constraints exclude all Go files"):
				problem.Cause = "package excluded by the selected build constraints"
				problem.Hint = "check the source target, GOOS, GOARCH, and build tags"
			}
		case packages.ParseError:
			problem.Kind, problem.Cause = "parsing", "Go syntax errors"
			problem.Hint = "inspect and fix the syntax errors in this module before scanning"
		case packages.TypeError:
			problem.Kind, problem.Cause = "type checking", "Go type checking failed"
			problem.Hint = "check --goos/--goarch against the intended build target and run the module's normal build checks"
		}
		problems = append(problems, problem)
	}
	return problems
}

func reportLoadProblems(result *inventory.Result, module string, problems []loadProblem) error {
	if len(problems) == 0 {
		return nil
	}
	problems = slices.Clone(problems)
	for i := range problems {
		problems[i].Module = module
	}
	slices.SortFunc(problems, func(a, b loadProblem) int {
		return strings.Compare(a.Package+"\x00"+a.Position+"\x00"+a.Kind+"\x00"+a.Cause, b.Package+"\x00"+b.Position+"\x00"+b.Kind+"\x00"+b.Cause)
	})
	problems = slices.Compact(problems)
	data, err := json.Marshal(problems)
	if err != nil {
		return fmt.Errorf("encode package-load diagnostics: %w", err)
	}
	result.Properties = append(result.Properties, cdx.Property{Name: "ciphertrail:package-load-errors", Value: string(data)})
	groups := map[string][]loadProblem{}
	var causes []string
	for _, problem := range problems {
		key := problem.Kind + ": " + problem.Cause
		if _, exists := groups[key]; !exists {
			causes = append(causes, key)
		}
		groups[key] = append(groups[key], problem)
	}
	slices.Sort(causes)
	var summaries []error
	for _, cause := range causes {
		group := groups[cause]
		packages := map[string]bool{}
		for _, problem := range group {
			packages[problem.Package] = true
		}
		noun := "packages"
		if len(packages) == 1 {
			noun = "package"
		}
		example := group[0].Package
		if group[0].Position != "" && group[0].Position != "-" {
			example += " at " + group[0].Position
		}
		summaries = append(summaries, fmt.Errorf("%s; %d %s affected (example %s); %s", cause, len(packages), noun, example, group[0].Hint))
	}
	return errors.Join(summaries...)
}

func (s Source) environment(offline bool) []string {
	overrides := map[string]string{
		"GOTOOLCHAIN": "local", "GOPACKAGESDRIVER": "off",
	}
	if offline {
		overrides["GOPROXY"], overrides["GONOPROXY"], overrides["GOSUMDB"] = "off", "none", "off"
	}
	if s.GOOS != "" {
		overrides["GOOS"] = s.GOOS
	}
	if s.GOARCH != "" {
		overrides["GOARCH"] = s.GOARCH
	}
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replace := overrides[name]; !replace {
			env = append(env, entry)
		}
	}
	for name, value := range overrides {
		env = append(env, name+"="+value)
	}
	return env
}

func moduleComponent(module *packages.Module) cdx.Component {
	component := cdx.Component{Type: "library", Name: module.Path, Version: module.Version}
	if module.Replace != nil {
		inventory.Property(&component, "requested-module", module.Path+"@"+module.Version)
		inventory.Property(&component, "module-replacement", module.Replace.Path)
		component.Version = module.Replace.Version
		if module.Replace.Version != "" {
			component.Name = module.Replace.Path
		}
	}
	component.PackageURL = inventory.GoPURL(component.Name, component.Version)
	return component
}

func moduleIdentity(module *packages.Module) string {
	if module == nil {
		return "stdlib"
	}
	if module.Replace != nil {
		return module.Replace.Path + "@" + module.Replace.Version
	}
	return module.Path
}

func excluded(name string) bool {
	return strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules"
}

func relative(root, path string) string {
	value, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(value)
}

func inside(root, path string) bool {
	value, err := filepath.Rel(root, path)
	if err != nil || value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return false
	}
	for _, name := range strings.Split(filepath.Dir(value), string(filepath.Separator)) {
		if name != "." && excluded(name) {
			return false
		}
	}
	return true
}

func cryptoPackage(path string) bool {
	return path == "crypto" || strings.HasPrefix(path, "crypto/") || strings.HasPrefix(path, "golang.org/x/crypto/")
}

func callSymbol(call *ssa.CallCommon) (path, name, symbol string) {
	object := callObject(call)
	if object == nil || object.Pkg() == nil {
		return "", "", ""
	}
	if call.IsInvoke() {
		return object.Pkg().Path(), object.Name(), object.FullName()
	}
	return object.Pkg().Path(), object.Name(), object.String()
}

func callObject(call *ssa.CallCommon) *types.Func {
	if call.IsInvoke() {
		return call.Method
	}
	function := call.StaticCallee()
	if function == nil {
		return nil
	}
	object, _ := function.Object().(*types.Func)
	return object
}

type apiIdentity struct{ path, receiver, name string }

func calledAPI(call *ssa.CallCommon) apiIdentity {
	object := callObject(call)
	if object == nil || object.Pkg() == nil {
		return apiIdentity{}
	}
	api := apiIdentity{path: object.Pkg().Path(), name: object.Name()}
	signature, ok := object.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return api
	}
	receiver := types.Unalias(signature.Recv().Type())
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = types.Unalias(pointer.Elem())
	}
	if named, ok := receiver.(*types.Named); ok {
		api.receiver = named.Obj().Name()
	}
	return api
}
