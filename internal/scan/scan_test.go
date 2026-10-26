package scan

import (
	"context"
	"errors"
	"reflect"
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

func TestProjectContextPreservesCollectorFactsAndPartialFailures(t *testing.T) {
	var collected inventory.Result
	evidence := inventory.Evidence{Kind: "configured", Collector: "fixture", Location: "app.go", Line: 3}
	module := collected.Add(cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "local-module"}, evidence, "")
	provider := collected.Add(cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "imported-library"}, evidence, "")
	hash := collected.Add(inventory.Algorithm("SHA-256", cdx.CryptoPrimitiveHash), evidence, module)
	certificate := collected.Add(inventory.ConfiguredCertificate("configured certificate", "", nil), evidence, "")
	collected.DependOn(hash, provider)
	collected.Subjects = []string{module}
	partial := errors.New("partial collection")
	collector := collectorFunc(func(context.Context) (inventory.Result, error) {
		return collected, partial
	})
	root := t.TempDir()
	result, err := (composed{projectRoot: root, collectors: []inventory.Collector{collector}}).Collect(context.Background())
	if !errors.Is(err, partial) || len(result.Subjects) != 1 || len(result.Entries) != len(collected.Entries)+1 {
		t.Fatalf("project context lost a partial failure or created wrong subjects: %v %+v", err, result.Subjects)
	}
	project := result.Subjects[0]
	for index, original := range collected.Entries {
		wrapped := result.Entries[index]
		if !reflect.DeepEqual(original.Component, wrapped.Component) || !reflect.DeepEqual(original.Evidence, wrapped.Evidence) {
			t.Fatal("project wrapping changed collected components, identities, or evidence")
		}
		switch original.Component.BOMRef {
		case module, certificate:
			if wrapped.Parent != project {
				t.Fatal("top-level local context is not owned by the project")
			}
		case hash:
			if wrapped.Parent != module {
				t.Fatal("existing collector ownership was replaced")
			}
		case provider:
			if wrapped.Parent != "" {
				t.Fatal("an ordinary dependency was mislabeled as project-owned code")
			}
		}
	}
	if !reflect.DeepEqual(collected.Dependencies, result.Dependencies) {
		t.Fatal("project context changed ordinary implementation dependencies")
	}
	for _, entry := range collected.Entries {
		if entry.Parent == project {
			t.Fatal("project wrapping mutated the collector's original result")
		}
	}
}

func TestProjectContextSurvivesCancellationAndRejectsMissingSubjects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	collector := collectorFunc(func(context.Context) (inventory.Result, error) {
		t.Fatal("cancelled project invoked a collector")
		return inventory.Result{}, nil
	})
	result, err := (composed{projectRoot: t.TempDir(), collectors: []inventory.Collector{collector}}).Collect(ctx)
	if !errors.Is(err, context.Canceled) || len(result.Subjects) != 1 || len(result.Entries) != 1 {
		t.Fatal("cancellation was hidden or known project context was lost")
	}
	invalid := collectorFunc(func(context.Context) (inventory.Result, error) {
		return inventory.Result{Subjects: []string{"missing"}}, nil
	})
	if _, err := (composed{projectRoot: t.TempDir(), collectors: []inventory.Collector{invalid}}).Collect(context.Background()); err == nil {
		t.Fatal("project wrapping hid a dangling collector subject")
	}
}
