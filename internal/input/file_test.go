package input

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFileContentIsReusableAndBounded(t *testing.T) {
	t.Parallel()
	file := NewFile("fixture", -1, strings.NewReader("abcdef"))
	prefix, err := file.Prefix(context.Background(), 3)
	if err != nil || string(prefix) != "abc" {
		t.Fatalf("prefix=%q error=%v", prefix, err)
	}
	for range 2 {
		data, err := file.ReadAll(context.Background(), 6)
		if err != nil || string(data) != "abcdef" {
			t.Fatalf("content was consumed or corrupted: %q %v", data, err)
		}
	}
	if _, err := file.ReadAll(context.Background(), 5); err == nil {
		t.Fatal("cached content bypassed the detector limit")
	}
	prefix, err = file.Prefix(context.Background(), 512)
	if err != nil || string(prefix) != "abcdef" {
		t.Fatal("prefix after content read lost the file")
	}
}

func TestOneDetectorLimitDoesNotPoisonAnotherDetector(t *testing.T) {
	file := NewFile("stream", -1, strings.NewReader("abcdef"))
	if _, err := file.ReadAll(context.Background(), 2); err == nil {
		t.Fatal("small detector limit was not enforced")
	}
	prefix, err := file.Prefix(context.Background(), 4)
	if err != nil || string(prefix) != "abcd" {
		t.Fatalf("partial buffering corrupted the prefix: %q %v", prefix, err)
	}
	data, err := file.ReadAll(context.Background(), 6)
	if err != nil || string(data) != "abcdef" {
		t.Fatalf("larger detector could not inspect the same stream: %q %v", data, err)
	}
}

func TestFileLimitsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name string
		size int64
		data string
	}{
		{"declared-oversize", 100, "x"},
		{"unknown-oversize", -1, "oversize"},
		{"growing-input", 1, "oversize"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := NewFile(test.name, test.size, strings.NewReader(test.data))
			if _, err := file.ReadAll(context.Background(), 4); err == nil {
				t.Fatal("oversized input accepted")
			}

		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	file := NewFile("cancelled", 0, strings.NewReader(""))
	if _, err := file.Prefix(ctx, 4); !errors.Is(err, context.Canceled) {
		t.Fatalf("prefix ignored cancellation: %v", err)
	}
	if _, err := file.ReadAll(ctx, 4); !errors.Is(err, context.Canceled) {
		t.Fatalf("content ignored cancellation: %v", err)
	}
}
