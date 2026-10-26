package input

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"cadi/internal/inventory"
	"cadi/internal/scope"
)

// Local opens selected local files without following symbolic links.
type Local struct {
	Path      string
	Selection *scope.Selection
}

// Walk uses a supplied discovery snapshot or discovers the explicit target once.
func (s Local) Walk(ctx context.Context, visit func(*File) error) (inventory.Result, error) {
	var result inventory.Result
	selection := s.Selection
	var failures error
	if selection == nil {
		discovered, err := scope.Discover(ctx, s.Path, scope.Options{ClassifyHelm: true, SkipReports: true})
		selection, failures = &discovered, err
	}
	for _, omission := range selection.Omissions {
		if omission.Reason == "link-or-special-file" {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: omission.Path, Message: "link or special file not followed"})
		}
	}
	for _, selected := range selection.Files {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(failures, err)
		}
		if err := visitLocal(ctx, selected, visit); err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", selected.Location, err))
		}
	}
	return result, errors.Join(failures, ctx.Err())
}

func visitLocal(ctx context.Context, selected scope.File, visit func(*File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := os.Lstat(selected.Path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("artifact is not a regular file")
	}
	relative, err := filepath.Rel(selected.Root, selected.Path)
	if err != nil {
		return err
	}
	reader, err := os.OpenInRoot(selected.Root, relative)
	if err != nil {
		return err
	}
	defer reader.Close()
	after, err := reader.Stat()
	if err != nil {
		return err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return fmt.Errorf("input changed while opening it")
	}
	file := NewFile(selected.Location, after.Size(), reader)
	file.Explicit, file.RandomAccess, file.HelmTemplate = selected.Explicit, reader, selected.HelmTemplate
	file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: selected.Location}
	return visit(file)
}
