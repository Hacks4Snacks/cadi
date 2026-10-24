package goscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
)

func loadExclusions(root string, specified []string) ([]string, error) {
	var exclusions []string
	add := func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\*?[]!:\x00\r\n") {
			return errors.New("expected a literal source-relative file or directory path; glob patterns, negation, and absolute paths are not supported")
		}
		for _, segment := range strings.Split(value, "/") {
			if segment == ".." {
				return errors.New("source exclusion must not traverse outside its root")
			}
		}
		value = path.Clean(value)
		if value == "." {
			return errors.New("source exclusion must name a file or directory beneath the root")
		}
		exclusions = append(exclusions, value)
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

func sourcePathExcluded(root, filename string, exclusions []string) bool {
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

func isolatedWorkspace(ctx context.Context, directory string, env []string) ([]string, func() error, error) {
	command := exec.CommandContext(ctx, "go", "env", "GOWORK")
	command.Dir, command.Env = directory, env
	data, err := command.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("locate Go workspace: %w", err)
	}
	path := strings.TrimSpace(string(data))
	if path == "" || path == "off" {
		return env, func() error { return nil }, nil
	}
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	work, err := modfile.ParseWork(path, data, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("parse Go workspace: %w", err)
	}
	var uses []*modfile.Use
	for _, use := range work.Use {
		usePath := use.Path
		if !filepath.IsAbs(usePath) {
			usePath = filepath.Join(filepath.Dir(path), usePath)
		}
		uses = append(uses, &modfile.Use{Path: usePath, ModulePath: use.ModulePath})
	}
	work.SetUse(uses)
	for _, replacement := range work.Replace {
		if replacement.New.Version == "" && !filepath.IsAbs(replacement.New.Path) {
			if err := work.AddReplace(replacement.Old.Path, replacement.Old.Version,
				filepath.Join(filepath.Dir(path), replacement.New.Path), ""); err != nil {
				return nil, nil, err
			}
		}
	}
	work.Cleanup()
	temporary, err := os.MkdirTemp("", "ciphertrail-workspace-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() error { return os.RemoveAll(temporary) }
	copyPath := filepath.Join(temporary, "go.work")
	if err := os.WriteFile(copyPath, modfile.Format(work.Syntax), 0600); err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	sum, err := os.ReadFile(path + ".sum")
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, errors.Join(err, cleanup())
	}
	if err == nil {
		if err := os.WriteFile(copyPath+".sum", sum, 0600); err != nil {
			return nil, nil, errors.Join(err, cleanup())
		}
	}
	// Go may update go.work.sum even with -mod=readonly; only this private copy may change.
	isolated := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, "GOWORK=") {
			isolated = append(isolated, entry)
		}
	}
	isolated = append(isolated, "GOWORK="+copyPath)
	return isolated, cleanup, nil
}
