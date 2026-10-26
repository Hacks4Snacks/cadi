// Package pyscan inventories Python cryptography without importing or executing target code.
package pyscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/scope"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Source analyzes the selected Python source files using a trusted, isolated AST frontend.
type Source struct {
	Selection   scope.Selection
	interpreter string
}

// Files selects Python modules, excluding conventional test names unless explicitly supplied.
func Files(files []scope.File) []scope.File {
	var selected []scope.File
	for _, file := range files {
		name := filepath.Base(file.Path)
		if !strings.HasSuffix(name, ".py") {
			continue
		}
		if !file.Explicit && (strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py") || name == "conftest.py") {
			continue
		}
		selected = append(selected, file)
	}
	return selected
}

// Collect returns configured findings and explicit parser/coverage failures.
func (s Source) Collect(ctx context.Context) (result inventory.Result, returnErr error) {
	files := Files(s.Selection.Files)
	skipped := 0
	for _, file := range s.Selection.Files {
		if strings.HasSuffix(file.Path, ".py") {
			skipped++
		}
	}
	skipped -= len(files)
	attempted := 0
	defer func() {
		status, reason := "completed", ""
		if len(files) == 0 {
			status, reason = "not-applicable", "no selected Python source files"
		} else if returnErr != nil {
			status = "failed"
		}
		refs := map[string]bool{}
		for _, entry := range result.Entries {
			if entry.Component.CryptoProperties != nil {
				refs[entry.Component.BOMRef] = true
			}
		}
		result.Coverage = append(result.Coverage, inventory.Coverage{
			Analyzer: "python", Status: status, Files: attempted, Findings: len(refs), Skipped: skipped, Reason: reason,
		})
	}()
	if len(files) == 0 {
		return result, nil
	}
	interpreter := s.interpreter
	if interpreter == "" {
		var err error
		interpreter, err = exec.LookPath("python3")
		if err != nil {
			return result, errors.New("Python analysis requires Python 3.10+ (python3 on PATH); install it or deselect the python analyzer")
		}
		interpreter, err = filepath.EvalSymlinks(interpreter)
		if err != nil {
			return result, fmt.Errorf("resolve Python interpreter: %w", err)
		}
		relative, err := filepath.Rel(s.Selection.Root, interpreter)
		if err == nil && filepath.IsLocal(relative) {
			return result, errors.New("Python interpreter resolves inside the source tree; select a trusted interpreter outside the source using PATH")
		}
	}
	type document struct {
		file scope.File
		ast  parsedFile
	}
	var documents []document
	var failures error
	var mutations []string
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(failures, err)
		}
		attempted++
		data, err := readSource(ctx, file)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", file.Location, err))
			continue
		}
		parsed, err := parse(ctx, interpreter, data)
		if parsed.Version != "" {
			result.Metadata("python-parser-version", parsed.Version)
		}
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", file.Location, err))
			continue
		}
		documents = append(documents, document{file: file, ast: parsed})
		mutations = append(mutations, parsed.Mutations...)
	}
	slices.Sort(mutations)
	mutations = slices.Compact(mutations)
	parent := result.Add(cdx.Component{Type: cdx.ComponentTypeApplication,
		Name: filepath.Base(s.Selection.Root) + " (Python source)", BOMRef: inventory.Ref("python-source", s.Selection.Root)},
		inventory.Evidence{Kind: "present", Collector: "python", Location: s.Selection.Root}, "")
	providers := map[string]string{}
	for _, document := range documents {
		shadowed, err := localProviders(s.Selection.Root, document.file.Path)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: inspect local Python imports: %w", document.file.Location, err))
			continue
		}
		for _, issue := range document.ast.Issues {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
				Location: document.file.Location, Line: issue.Line, Message: "Python analysis: " + issue.Message,
			})
		}
		for _, call := range document.ast.Calls {
			call.Value = invalidate(call.Value, shadowed, mutations)
			name := symbol(call.Value.Base)
			if name == "" {
				hint := ""
				if call.Value.Base != nil {
					hint = call.Value.Base.Hint
					if hint == "" {
						hint = instance(call.Value.Base.Base)
					}
				}
				if cryptoNamespace(hint) || httpNamespace(hint) {
					result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: document.file.Location,
						Line: call.Line, Message: "Python cryptographic callable binding is ambiguous or shadowed: " + hint})
				}
				continue
			}
			http, isHTTP := httpCallModel(name)
			if !cryptoNamespace(name) && !isHTTP {
				continue
			}
			if shadowed[strings.Split(name, ".")[0]] || mutated(name, mutations) {
				result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: document.file.Location, Line: call.Line,
					Message: "Python cryptographic API binding is not established because of a local module or observed mutation: " + name})
				continue
			}
			if nonAsset(name) {
				continue
			}
			evidence := inventory.Evidence{Kind: "configured", Collector: "python", Location: document.file.Location, Line: call.Line, Symbol: name}
			var component cdx.Component
			if isHTTP {
				switch http.scheme(call.Value) {
				case schemeHTTPS:
					component = httpsConfiguration()
				case schemeHTTP:
					continue
				default:
					result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
						Location: evidence.Location, Line: evidence.Line,
						Message: "Python HTTP URL scheme is not established as HTTP/HTTPS; TLS use was not inferred: " + name,
					})
					continue
				}
			} else {
				var matched bool
				component, matched = recognize(name, call.Value, &evidence)
				if !matched {
					result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
						Location: evidence.Location, Line: evidence.Line, Message: "Python cryptographic API not modeled: " + name,
					})
					continue
				}
			}
			ref := result.Add(component, evidence, parent)
			result.DependOn(ref, provider(&result, providers, s.Selection.Root, name, evidence))
		}
		for _, assignment := range document.ast.Settings {
			assignment.Receiver = invalidate(assignment.Receiver, shadowed, mutations)
			assignment.Value = invalidate(assignment.Value, shadowed, mutations)
			kind := instance(&assignment.Receiver)
			if kind != "ssl.SSLContext" || shadowed["ssl"] || mutated(kind, mutations) {
				continue
			}
			evidence := inventory.Evidence{Kind: "configured", Collector: "python", Location: document.file.Location,
				Line: assignment.Line, Symbol: kind + "." + assignment.Attribute}
			component, matched := sslSetting(assignment, &evidence)
			if matched {
				ref := result.Add(component, evidence, parent)
				result.DependOn(ref, provider(&result, providers, s.Selection.Root, "ssl", evidence))
			}
		}
	}
	return result, failures
}

func readSource(ctx context.Context, file scope.File) ([]byte, error) {
	var data []byte
	_, err := (input.Local{Selection: &scope.Selection{Files: []scope.File{file}}}).Walk(ctx, func(file *input.File) error {
		var err error
		data, err = file.ReadAll(ctx, maxSourceBytes)
		return err
	})
	return data, err
}

func localProviders(root, filename string) (map[string]bool, error) {
	blocked := map[string]bool{}
	for _, name := range []string{"hashlib", "hmac", "ssl", "secrets", "os", "cryptography", "Crypto", "Cryptodome", "OpenSSL", "jwt", "paramiko", "requests", "httpx", "urllib3", "urllib", "http"} {
		for _, directory := range []string{root, filepath.Join(root, "src"), filepath.Dir(filename)} {
			for _, path := range []string{filepath.Join(directory, name+".py"), filepath.Join(directory, name)} {
				_, err := os.Lstat(path)
				if err == nil {
					blocked[name] = true
				} else if !os.IsNotExist(err) {
					return nil, err
				}
			}
		}
	}
	return blocked, nil
}

func mutated(symbol string, mutations []string) bool {
	symbol = canonicalHTTPName(symbol)
	for _, mutation := range mutations {
		mutation = canonicalHTTPName(mutation)
		mutation = strings.TrimSuffix(strings.TrimSuffix(mutation, ".__new__"), ".__init__")
		if symbol == mutation || strings.HasPrefix(symbol, mutation+".") {
			return true
		}
	}
	return false
}

func provider(result *inventory.Result, refs map[string]string, root, symbol string, evidence inventory.Evidence) string {
	namespace := strings.Split(symbol, ".")[0]
	name := namespace
	switch namespace {
	case "hashlib", "hmac", "ssl", "secrets", "os", "urllib", "http":
		name = "Python standard library"
	}
	if refs[name] == "" {
		component := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: name, BOMRef: inventory.Ref("python-provider", root, name)}
		inventory.Property(&component, "scope", "source import/API namespace; installed distribution, version, and target interpreter are not established")
		refs[name] = result.Add(component, evidence, "")
	}
	return refs[name]
}
