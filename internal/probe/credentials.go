package probe

import (
	"fmt"
	"io"
	"os"
)

func readCredential(path string) ([]byte, error) {
	const limit = 16 << 20
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("TLS credential must be a regular file no larger than 16 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("TLS credential exceeded 16 MiB while reading")
	}
	return data, nil
}
