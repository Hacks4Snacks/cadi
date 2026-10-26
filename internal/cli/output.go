package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cadi/internal/inventory"
)

type outputKind int

const (
	outputCBOM outputKind = iota
	outputScanReport
)

func (kind outputKind) label() string {
	if kind == outputScanReport {
		return "scan report"
	}
	return "CBOM"
}

type outputTarget struct {
	path   string
	before os.FileInfo
	kind   outputKind
}

func prepareOutput(path string, inputs []string, kind outputKind) (*outputTarget, error) {
	if path == "-" {
		return nil, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	target := &outputTarget{path: filepath.Join(parent, filepath.Base(absolute)), kind: kind}
	info, err := os.Lstat(target.path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("output must be a regular file, not a symlink or special file")
		}
		target.before = info
	}
	for _, input := range inputs {
		inputPath, err := filepath.Abs(input)
		if err != nil {
			return nil, err
		}
		resolved, resolveErr := filepath.EvalSymlinks(inputPath)
		if resolveErr == nil {
			inputPath = resolved
		} else if !os.IsNotExist(resolveErr) {
			return nil, fmt.Errorf("resolve input for output protection: %w", resolveErr)
		} else {
			inputParent, parentErr := filepath.EvalSymlinks(filepath.Dir(inputPath))
			if parentErr == nil {
				inputPath = filepath.Join(inputParent, filepath.Base(inputPath))
			} else if !os.IsNotExist(parentErr) {
				return nil, fmt.Errorf("resolve input directory for output protection: %w", parentErr)
			}
		}
		if inputPath == target.path {
			return nil, errors.New("output would overwrite a scan input or TLS credential")
		}
		if target.before != nil {
			inputInfo, err := os.Stat(input)
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			if err == nil && os.SameFile(target.before, inputInfo) {
				return nil, errors.New("output is a hard link to a scan input or TLS credential")
			}
		}
	}
	if target.before != nil {
		file, err := os.Open(target.path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		var header struct {
			BOMFormat     string `json:"bomFormat"`
			ReportFormat  string `json:"reportFormat"`
			ReportVersion int    `json:"reportVersion"`
			Tool          struct {
				Name string `json:"name"`
			} `json:"tool"`
			Metadata struct {
				Tools struct {
					Components []struct{ Name string } `json:"components"`
				} `json:"tools"`
			} `json:"metadata"`
		}
		decoder := json.NewDecoder(io.LimitReader(file, 256<<20))
		if err := decoder.Decode(&header); err != nil {
			return nil, fmt.Errorf("existing output is not a CADI %s; refusing to overwrite it", kind.label())
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, errors.New("existing output contains trailing data; refusing to overwrite it")
		}
		ours := false
		switch kind {
		case outputCBOM:
			if header.BOMFormat == "CycloneDX" {
				for _, tool := range header.Metadata.Tools.Components {
					ours = ours || inventory.IsToolName(tool.Name)
				}
			}
		case outputScanReport:
			ours = inventory.IsScanReportFormat(header.ReportFormat) && header.ReportVersion == 1 && inventory.IsToolName(header.Tool.Name)
		}
		if !ours {
			return nil, fmt.Errorf("existing output is not a CADI %s; choose a new path", kind.label())
		}
	}
	return target, nil
}

func (o *outputTarget) write(data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(o.path), ".cadi-*.tmp")
	if err != nil {
		return fmt.Errorf("create %s output: %w", o.kind.label(), err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write %s output: %w", o.kind.label(), err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync %s output: %w", o.kind.label(), err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	current, err := os.Lstat(o.path)
	if o.before == nil {
		if err == nil || !os.IsNotExist(err) {
			return errors.New("output path changed during collection; refusing to overwrite it")
		}
	} else if err != nil || !current.Mode().IsRegular() || !os.SameFile(o.before, current) ||
		!current.ModTime().Equal(o.before.ModTime()) || current.Size() != o.before.Size() {
		return errors.New("output file changed during collection; refusing to overwrite it")
	}
	if err := os.Rename(temporary, o.path); err != nil {
		return fmt.Errorf("replace %s output: %w", o.kind.label(), err)
	}
	return nil
}
