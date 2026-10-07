package storage

import (
	"context"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/accounting"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/reference"
)

func TestRegistryAccountingDisabledByDefault(t *testing.T) {
	reg, err := NewRegistry(context.Background(), inmemory.New())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	r := reg.(*registry)
	if r.accounting != nil {
		t.Fatal("accounting service must be nil without the option")
	}
}

func TestRegistryAccountingOptionPropagates(t *testing.T) {
	budgets, err := accounting.NewBudgets("10GiB", nil)
	if err != nil {
		t.Fatalf("NewBudgets: %v", err)
	}
	svc, err := accounting.NewService(inmemory.New(), budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	reg, err := NewRegistry(context.Background(), inmemory.New(), AccountingService(svc))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	r := reg.(*registry)
	if r.accounting == nil {
		t.Fatal("accounting service not wired into registry")
	}
	if !r.accounting.ReleaseOnUntag() {
		t.Error("releaseOnUntag toggle not propagated")
	}

	named, err := reference.WithName("team-a/app")
	if err != nil {
		t.Fatalf("WithName: %v", err)
	}
	repo, err := r.Repository(context.Background(), named)
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}
	if repo.(*repository).registry.accounting == nil {
		t.Fatal("accounting service not reachable from a repository")
	}
}
