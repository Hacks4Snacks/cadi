package pyscan

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

//go:embed frontend.py
var frontend string

const maxSourceBytes = 8 << 20
const maxFrontendBytes = 16 << 20
const frontendTimeout = 10 * time.Second

type value struct {
	Kind     string           `json:"kind"`
	Text     string           `json:"text"`
	Hint     string           `json:"hint"`
	Integer  int64            `json:"integer"`
	Length   int64            `json:"length"`
	Base     *value           `json:"base"`
	Args     []value          `json:"args"`
	Keywords map[string]value `json:"keywords"`
}

type call struct {
	Line   int   `json:"line"`
	Column int   `json:"column"`
	Value  value `json:"value"`
}

type setting struct {
	Line      int    `json:"line"`
	Attribute string `json:"attribute"`
	Receiver  value  `json:"receiver"`
	Value     value  `json:"value"`
}

type parsedFile struct {
	Protocol  int       `json:"protocol"`
	Version   string    `json:"version"`
	Calls     []call    `json:"calls"`
	Settings  []setting `json:"settings"`
	Mutations []string  `json:"mutations"`
	Issues    []struct {
		Line    int    `json:"line"`
		Message string `json:"message"`
	} `json:"issues"`
	Error *struct {
		Kind string `json:"kind"`
		Line int    `json:"line"`
	} `json:"error"`
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.buffer.Len() {
		b.exceeded = true
		b.cancel()
		return 0, errors.New("Python frontend output limit exceeded")
	}
	return b.buffer.Write(data)
}

func parse(ctx context.Context, interpreter string, source []byte) (parsedFile, error) {
	var result parsedFile
	if len(source) > maxSourceBytes {
		return result, fmt.Errorf("Python source exceeds the %d-byte limit", maxSourceBytes)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	deadline, cancel := context.WithTimeout(ctx, frontendTimeout)
	defer cancel()
	command := exec.CommandContext(deadline, interpreter, "-I", "-S", "-B", "-c", frontend)
	command.Dir = os.TempDir()
	command.Stdin = bytes.NewReader(source)
	command.WaitDelay = time.Second
	stdout := &boundedBuffer{limit: maxFrontendBytes, cancel: cancel}
	stderr := &boundedBuffer{limit: 64 << 10, cancel: cancel}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return result, errors.New("Python frontend exceeded its output limit")
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if deadline.Err() != nil {
		return result, fmt.Errorf("Python frontend timed out after %s: %w", frontendTimeout, deadline.Err())
	}
	if err != nil {
		return result, errors.New("isolated Python AST frontend failed; target code was not executed")
	}
	if err := json.Unmarshal(stdout.buffer.Bytes(), &result); err != nil {
		return parsedFile{}, errors.New("Python AST frontend returned an invalid response")
	}
	version := strings.Split(result.Version, ".")
	if result.Protocol != 1 || len(version) != 3 {
		return parsedFile{}, errors.New("Python AST frontend returned an invalid response")
	}
	for _, number := range version {
		if parsed, err := strconv.Atoi(number); err != nil || parsed < 0 {
			return parsedFile{}, errors.New("Python AST frontend returned an invalid response")
		}
	}
	if result.Error != nil {
		switch result.Error.Kind {
		case "runtime":
			return result, errors.New("Python analysis requires a Python 3.10+ interpreter")
		case "syntax":
			return result, fmt.Errorf("Python syntax or source-encoding error at line %d", result.Error.Line)
		case "limit":
			return result, errors.New("Python AST complexity limit exceeded")
		default:
			return result, errors.New("Python AST analysis failed")
		}
	}
	if result.Calls == nil || result.Settings == nil || result.Mutations == nil || result.Issues == nil {
		return parsedFile{}, errors.New("Python AST frontend returned an invalid response")
	}
	return result, nil
}
