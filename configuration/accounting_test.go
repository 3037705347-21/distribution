package configuration

import (
	"testing"
	"time"

	"go.yaml.in/yaml/v2"
)

func TestAccountingConfigAbsentByDefault(t *testing.T) {
	var cfg Configuration
	if err := yaml.Unmarshal([]byte("version: 0.1\n"), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Accounting.Enabled {
		t.Fatal("accounting must default to disabled")
	}
}

func TestAccountingConfigParsing(t *testing.T) {
	const doc = `
version: 0.1
accounting:
  enabled: true
  releaseonuntag: false
  reservationttl: 12h
  reconcile:
    onstart: true
    interval: 30m
  budget:
    default: 10GiB
    repositories:
      team-a/*: 1GiB
      library/nginx: 100MiB
`
	var cfg Configuration
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	a := cfg.Accounting
	if !a.Enabled {
		t.Error("expected enabled=true")
	}
	if a.ReleaseOnUntag == nil || *a.ReleaseOnUntag {
		t.Error("expected explicit releaseonuntag=false")
	}
	if a.ReservationTTL != 12*time.Hour {
		t.Errorf("reservationttl = %v", a.ReservationTTL)
	}
	if !a.Reconcile.OnStart || a.Reconcile.Interval != 30*time.Minute {
		t.Errorf("reconcile = %+v", a.Reconcile)
	}
	if a.Budget.Default != "10GiB" {
		t.Errorf("budget.default = %q", a.Budget.Default)
	}
	if got := a.Budget.Repositories["team-a/*"]; got != "1GiB" {
		t.Errorf("team-a/* budget = %q", got)
	}
	if got := a.Budget.Repositories["library/nginx"]; got != "100MiB" {
		t.Errorf("library/nginx budget = %q", got)
	}
}
