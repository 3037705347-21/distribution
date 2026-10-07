package accounting

import (
	"testing"
)

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"1024", 1024},
		{" 2048 ", 2048},
		{"1B", 1},
		{"1kib", 1 << 10},
		{"1KiB", 1 << 10},
		{"1MiB", 1 << 20},
		{"1GiB", 1 << 30},
		{"2GiB", 2 << 30},
		{"1KB", 1000},
		{"1MB", 1000 * 1000},
		{"1GB", 1000 * 1000 * 1000},
		{"10g", 10 << 30},
	}
	for _, tc := range cases {
		got, err := ParseSize(tc.in)
		if err != nil {
			t.Fatalf("ParseSize(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseSizeErrors(t *testing.T) {
	for _, in := range []string{"", "abc", "1.5GiB", "10XB", "99999999999999999GiB", "GiB", "-1"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) expected error, got nil", in)
		}
	}
}

func TestBudgetsMatching(t *testing.T) {
	b, err := NewBudgets("10GiB", map[string]string{
		"team-a/*":       "1GiB",
		"team-a/special": "2GiB",
		"*":              "500MiB",
	})
	if err != nil {
		t.Fatalf("NewBudgets: %v", err)
	}

	cases := []struct {
		repo    string
		limit   int64
		limited bool
	}{
		{"team-a/special", 2 << 30, true}, // exact name beats glob
		{"team-a/app", 1 << 30, true},     // team-a glob wins over default
		{"busybox", 500 << 20, true},      // single-component repo matches "*"
		// "*" does not cross "/", so multi-component repos without a more
		// specific rule fall back to the default budget.
		{"team-b/app", 10 << 30, true},
		{"deep/team-a/app", 10 << 30, true},
	}
	for _, tc := range cases {
		limit, limited := b.Limit(tc.repo)
		if limit != tc.limit || limited != tc.limited {
			t.Errorf("Limit(%q) = (%d,%v), want (%d,%v)", tc.repo, limit, limited, tc.limit, tc.limited)
		}
	}
}

func TestBudgetsDefaultAndUnlimited(t *testing.T) {
	// default only
	b, err := NewBudgets("100MB", nil)
	if err != nil {
		t.Fatalf("NewBudgets: %v", err)
	}
	limit, limited := b.Limit("anything/repo")
	if !limited || limit != 100*1000*1000 {
		t.Errorf("default budget = (%d,%v)", limit, limited)
	}

	// no default and no rule: unlimited
	b2, err := NewBudgets("", nil)
	if err != nil {
		t.Fatalf("NewBudgets: %v", err)
	}
	limit, limited = b2.Limit("anything/repo")
	if limited || limit != Unlimited {
		t.Errorf("unlimited budget = (%d,%v)", limit, limited)
	}

	// nil Budgets must be safe.
	limit, limited = (*Budgets)(nil).Limit("repo")
	if limited || limit != Unlimited {
		t.Errorf("nil budget = (%d,%v)", limit, limited)
	}

	// zero limit is a valid explicit deny
	b3, err := NewBudgets("", map[string]string{"frozen/*": "0"})
	if err != nil {
		t.Fatalf("NewBudgets: %v", err)
	}
	limit, limited = b3.Limit("frozen/repo")
	if !limited || limit != 0 {
		t.Errorf("zero budget = (%d,%v)", limit, limited)
	}
}

func TestBudgetsInvalidConfig(t *testing.T) {
	if _, err := NewBudgets("not-a-size", nil); err == nil {
		t.Error("expected error for invalid default size")
	}
	if _, err := NewBudgets("", map[string]string{"bad[": "1GiB"}); err == nil {
		t.Error("expected error for invalid glob")
	}
	if _, err := NewBudgets("", map[string]string{"team-a/*": "bogus"}); err == nil {
		t.Error("expected error for invalid rule size")
	}
}
