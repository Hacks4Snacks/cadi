package detect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type fixtureDetector struct {
	calls int
	fail  error
}

func (*fixtureDetector) Name() string { return "fixture" }
func (*fixtureDetector) Match(file *input.File, _ []byte) bool {
	return strings.HasSuffix(file.Name, ".finding")
}
func (d *fixtureDetector) Detect(ctx context.Context, file *input.File) (inventory.Result, bool, error) {
	d.calls++
	var result inventory.Result
	data, err := file.ReadAll(ctx, 128)
	if err != nil {
		return result, true, err
	}
	if string(data) != "fixture" {
		return result, true, errors.New("fixture content was not preserved")
	}
	result.Add(inventory.Algorithm("fixture algorithm", cdx.CryptoPrimitiveOther), file.Evidence, file.Parent)
	return result, true, d.fail
}

func TestRegisteredDetectorWorksAcrossLocalAndImageInputs(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "new.finding"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := testutil.ImageArchive(t, map[string][]byte{"new.finding": []byte("fixture")})
	for name, source := range map[string]input.Source{
		"local": input.Local{Path: directory},
		"image": input.Image{Path: archive},
	} {
		t.Run(name, func(t *testing.T) {
			first, second := &fixtureDetector{}, &fixtureDetector{}
			result, err := (Collector{Source: source, Detectors: []Detector{first, second}}).Collect(context.Background())
			if err != nil || first.calls != 1 || second.calls != 1 {
				t.Fatalf("detector registration failed: calls=%d/%d err=%v", first.calls, second.calls, err)
			}
			if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
				t.Fatal(err)
			}
			for _, entry := range result.Entries {
				if entry.Component.Name == "fixture algorithm" && !strings.HasSuffix(entry.Evidence.Location, "new.finding") {
					t.Fatal("input provenance was lost")
				}
			}
		})
	}
}

func TestDetectorFailureDoesNotDiscardOtherFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.finding")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("fixture failure")
	failed, succeeded := &fixtureDetector{fail: want}, &fixtureDetector{}
	result, err := (Collector{Source: input.Local{Path: path}, Detectors: []Detector{failed, succeeded}}).Collect(context.Background())
	if !errors.Is(err, want) || succeeded.calls != 1 || len(result.Entries) != 2 {
		t.Fatalf("partial failure lost results: entries=%d err=%v", len(result.Entries), err)
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result, Err: err}}); err != nil {
		t.Fatal(err)
	}
}
