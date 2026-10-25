package goscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

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
