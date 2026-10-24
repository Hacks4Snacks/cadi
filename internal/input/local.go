package input

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"ciphertrail/internal/inventory"
)

// Local visits an explicit file or a directory without following symbolic links.
type Local struct{ Path string }

// Walk opens regular files only for the duration of each visitor call.
func (s Local) Walk(ctx context.Context, visit func(*File) error) (inventory.Result, error) {
	var result inventory.Result
	if err := ctx.Err(); err != nil {
		return result, err
	}
	root, err := filepath.Abs(s.Path)
	if err != nil {
		return result, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return result, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return result, fmt.Errorf("explicit artifact input is a symlink; supply its intended target directly")
	}
	if !info.IsDir() {
		return result, visitLocal(ctx, root, root, true, visit)
	}
	var failures error
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			failures = errors.Join(failures, err)
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		location, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		location = filepath.ToSlash(location)
		if entry.Type()&os.ModeSymlink != 0 {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: location, Message: "symlink not followed"})
			return nil
		}
		if !entry.Type().IsRegular() {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: location, Message: "non-regular file not read"})
			return nil
		}
		if err := visitLocal(ctx, path, location, false, visit); err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", location, err))
		}
		return nil
	})
	return result, errors.Join(failures, err)
}

func visitLocal(ctx context.Context, path, location string, explicit bool, visit func(*File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("artifact is not a regular file")
	}
	reader, err := os.Open(path)
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
	file := NewFile(location, after.Size(), reader)
	file.Explicit, file.RandomAccess = explicit, reader
	file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: location}
	return visit(file)
}
