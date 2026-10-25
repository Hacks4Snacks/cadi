// Package input provides read-only, streaming access to explicitly selected inputs.
package input

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"ciphertrail/internal/inventory"
)

// MaxAssetBytes bounds content buffered for detection.
const MaxAssetBytes int64 = 256 << 20

// Source visits files without choosing how their contents are analyzed.
type Source interface {
	Walk(context.Context, func(*File) error) (inventory.Result, error)
}

// File is valid only during its source's visitor callback.
// Detectors must not retain readers or mutate buffers returned by Prefix or ReadAll.
type File struct {
	Name         string
	Size         int64
	Explicit     bool
	HelmTemplate bool
	Evidence     inventory.Evidence
	Parent       string
	RandomAccess io.ReaderAt
	reader       io.Reader
	buffered     *bufio.Reader
	data         []byte
	read         bool
	readErr      error
}

// NewFile wraps a file stream; a negative size means its length is not known.
func NewFile(name string, size int64, reader io.Reader) *File {
	return &File{Name: name, Size: size, reader: reader}
}

func (f *File) stream(ctx context.Context) *bufio.Reader {
	if f.buffered == nil {
		f.buffered = bufio.NewReader(contextReader{ctx, f.reader})
	}
	return f.buffered
}

// Prefix inspects up to n bytes without consuming them, including short files.
func (f *File) Prefix(ctx context.Context, n int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n < 0 || n > 4096 {
		return nil, fmt.Errorf("prefix length must be between 0 and 4096")
	}
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.read || len(f.data) >= n {
		return f.data[:min(n, len(f.data))], nil
	}
	data, err := f.stream(ctx).Peek(n - len(f.data))
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if len(f.data) > 0 {
		prefix := make([]byte, 0, len(f.data)+len(data))
		data = append(append(prefix, f.data...), data...)
	}
	return data, err
}

// ReadAll buffers a file once, enforcing both the detector limit and the global cap.
func (f *File) ReadAll(ctx context.Context, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxAssetBytes {
		return nil, fmt.Errorf("content limit must be between 1 and %d bytes", MaxAssetBytes)
	}
	if f.Size > limit || int64(len(f.data)) > limit {
		return nil, fmt.Errorf("asset exceeds the %d-byte parsing limit", limit)
	}
	if !f.read {
		if f.readErr != nil {
			return nil, f.readErr
		}
		data, err := io.ReadAll(io.LimitReader(f.stream(ctx), limit+1-int64(len(f.data))))
		f.data = append(f.data, data...)
		f.readErr = err
		if err == nil && int64(len(f.data)) > limit {
			return nil, fmt.Errorf("asset grew beyond the %d-byte parsing limit", limit)
		}
		f.read = true
	}
	if f.readErr != nil {
		return nil, f.readErr
	}
	return f.data, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
