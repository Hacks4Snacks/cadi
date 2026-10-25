package scan

import (
	"context"
	"errors"
	"testing"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type collectorFunc func(context.Context) (inventory.Result, error)

func (c collectorFunc) Collect(ctx context.Context) (inventory.Result, error) { return c(ctx) }

func TestRunPreservesPartialFailuresAndAccountsForCancelledTargets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	want := errors.New("partial failure")
	partial := collectorFunc(func(context.Context) (inventory.Result, error) {
		var result inventory.Result
		result.Add(inventory.Algorithm("fixture", cdx.CryptoPrimitiveOther), inventory.Evidence{Kind: "configured"}, "")
		return result, want
	})
	stop := collectorFunc(func(context.Context) (inventory.Result, error) {
		cancel()
		return inventory.Result{}, nil
	})
	unexpected := collectorFunc(func(context.Context) (inventory.Result, error) {
		t.Fatal("cancelled target was invoked")
		return inventory.Result{}, nil
	})
	collections := Run(ctx, []Request{{"partial", "one", partial}, {"stop", "two", stop}, {"cancelled", "three", unexpected}})
	if len(collections) != 3 || len(collections[0].Result.Entries) != 1 ||
		!errors.Is(collections[0].Err, want) || !errors.Is(collections[2].Err, context.Canceled) {
		t.Fatalf("collection accounting failed: %+v", collections)
	}

}

func TestPythonSourceIsNotExecutedFromImages(t *testing.T) {
	request := imageRequest("unused-image", nil, []string{"python"})
	result, err := request.Collector.Collect(context.Background())
	if err != nil || len(result.Coverage) != 1 || result.Coverage[0].Analyzer != "python" ||
		result.Coverage[0].Status != "not-applicable" {
		t.Fatalf("Python image applicability was not explicit: %+v %v", result.Coverage, err)
	}
}
