package goscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

type moduleFiles struct {
	env       []string
	flags     []string
	unchanged map[string][]byte
	cleanup   func() error
	workspace bool
}

func isolateModuleFiles(ctx context.Context, directory string, env []string) (*moduleFiles, error) {
	env, cleanWork, err := isolatedWorkspace(ctx, directory, env)
	if err != nil {
		return nil, err
	}
	temporary, err := os.MkdirTemp("", "ciphertrail-module-")
	if err != nil {
		return nil, errors.Join(err, cleanWork())
	}
	files := &moduleFiles{
		env: env, unchanged: map[string][]byte{},
		cleanup: func() error { return errors.Join(os.RemoveAll(temporary), cleanWork()) },
	}
	fail := func(err error) (*moduleFiles, error) { return nil, errors.Join(err, files.cleanup()) }
	copyFile := func(source, target string, required bool) error {
		data, err := os.ReadFile(source)
		if err != nil && (required || !os.IsNotExist(err)) {
			return err
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			return err
		}
		if required {
			files.unchanged[target] = data
		}
		return nil
	}
	workPath := envValue(env, "GOWORK")
	if workPath == "" || workPath == "off" || workPath == "auto" {
		modPath := filepath.Join(temporary, "main.mod")
		if err := copyFile(filepath.Join(directory, "go.mod"), modPath, true); err != nil {
			return fail(fmt.Errorf("isolate go.mod: %w", err))
		}
		if err := copyFile(filepath.Join(directory, "go.sum"), filepath.Join(temporary, "main.sum"), false); err != nil {
			return fail(fmt.Errorf("isolate go.sum: %w", err))
		}
		files.env = setEnv(files.env, "GOWORK", "off")
		files.flags = []string{"-modfile=" + modPath}
		return files, nil
	}
	data, err := os.ReadFile(workPath)
	if err != nil {
		return fail(err)
	}
	files.unchanged[workPath] = data
	work, err := modfile.ParseWork(workPath, data, nil)
	if err != nil {
		return fail(fmt.Errorf("parse isolated workspace: %w", err))
	}
	overlay := struct{ Replace map[string]string }{Replace: map[string]string{}}
	for i, use := range work.Use {
		for _, suffix := range []string{"mod", "sum"} {
			source := filepath.Join(use.Path, "go."+suffix)
			target := filepath.Join(temporary, fmt.Sprintf("workspace-%d.%s", i, suffix))
			if err := copyFile(source, target, suffix == "mod"); err != nil {
				return fail(fmt.Errorf("isolate workspace manifest: %w", err))
			}
			overlay.Replace[source] = target
		}
	}
	overlayPath := filepath.Join(temporary, "overlay.json")
	data, err = json.Marshal(overlay)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(overlayPath, data, 0600); err != nil {
		return fail(err)
	}
	files.flags = []string{"-overlay=" + overlayPath}
	files.workspace = true
	return files, nil
}

func (m *moduleFiles) prepare(ctx context.Context, directory string, env, buildFlags, patterns []string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	env = setEnv(env, "GOWORK", envValue(m.env, "GOWORK"))
	env = setEnv(env, "GIT_TERMINAL_PROMPT", "0")
	moduleMode := "mod"
	if m.workspace {
		moduleMode = "readonly"
	}
	args := append([]string{"list", "-deps", "-mod=" + moduleMode}, buildFlags...)
	args = append(args, patterns...)
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir, command.Env = directory, env
	command.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	command.Stdout, command.Stderr = io.Discard, &stderr
	runErr := command.Run()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("dependency preparation interrupted: %w", err)
	}
	if runErr != nil {
		return fmt.Errorf("dependency preparation: %s", safeGoFailure(stderr.String()))
	}
	for path, before := range m.unchanged {
		after, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("verify isolated manifest: %w", err)
		}
		if !bytes.Equal(before, after) {
			return errors.New("dependency preparation requires module metadata changes; target manifests were not changed; fix the module with its normal build workflow")
		}
	}
	return nil
}

func needsDependencyPreparation(loaded []*packages.Package, err error) bool {
	needed := err != nil && dependencyMiss(err.Error())
	undeclared := err != nil && strings.Contains(err.Error(), "no required module provides")
	packages.Visit(loaded, nil, func(pkg *packages.Package) {
		for _, problem := range pkg.Errors {
			needed = needed || dependencyMiss(problem.Msg)
			undeclared = undeclared || strings.Contains(problem.Msg, "no required module provides")
		}
	})
	return needed && !undeclared
}

func dependencyMiss(message string) bool {
	return strings.Contains(message, "module lookup disabled by GOPROXY=off") ||
		strings.Contains(message, "missing go.sum entry") || strings.Contains(message, "updates to go.sum needed")
}

func safeGoFailure(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "updates to go.mod"), strings.Contains(lower, "go.mod is part of the overlay"):
		return "module metadata changes are required; target manifests remain unchanged; use the repository's normal build workflow to repair them"
	case strings.Contains(lower, "no required module provides"):
		return "the import is not provided by the declared modules; check go.mod requirements and replacements"
	case strings.Contains(lower, "missing go.sum"), strings.Contains(lower, "updates to go.sum"):
		return "required dependency checksums are unavailable; check the module's dependency preparation settings"
	case strings.Contains(lower, "goproxy=off"):
		return "required dependency is not cached and module lookup is disabled; rerun without --offline or correct the configured GOPROXY"
	case strings.Contains(lower, "403 forbidden"), strings.Contains(lower, "401 unauthorized"),
		strings.Contains(lower, "authentication"), strings.Contains(lower, "terminal prompts disabled"):
		return "dependency access denied; check private-module routing and existing Go/VCS credentials"
	case strings.Contains(lower, "404 not found"), strings.Contains(lower, "unknown revision"):
		return "the declared module version is unavailable or access is denied; check the version and private-module credentials"
	case strings.Contains(lower, "checksum mismatch"), strings.Contains(lower, "security error"):
		return "dependency checksum verification failed; inspect the module's normal Go download diagnostics"
	case strings.Contains(lower, "requires go"), strings.Contains(lower, "go version"):
		return "dependency requires a compatible local Go toolchain; automatic toolchain downloads are disabled"
	case strings.Contains(lower, "timeout"), strings.Contains(lower, "deadline"):
		return "dependency service timed out; retry with connectivity to the configured Go/VCS endpoints"
	case strings.Contains(lower, "no such host"), strings.Contains(lower, "connection refused"):
		return "dependency service is unreachable; check the configured Go proxy/VCS connectivity"
	default:
		return "Go dependency resolution failed; check module versions, private-module access, and the normal Go download diagnostics"
	}
}

func envValue(env []string, name string) string {
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		if key == name {
			return value
		}
	}
	return ""
}

func setEnv(env []string, name, value string) []string {
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, name+"=") {
			result = append(result, item)
		}
	}
	return append(result, name+"="+value)
}
