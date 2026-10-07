package accounting

import (
	"fmt"
	"path"
	"sort"
)

// Unlimited is returned as the limit for repositories without a configured
// budget: no admission control is applied.
const Unlimited int64 = -1

// budgetRule is a single repository budget pattern: glob (path.Match
// semantics, "*" does not cross a "/" component) mapped to a byte limit.
type budgetRule struct {
	pattern string
	limit   int64
}

// Budgets resolves the byte budget for a repository name. Exact repository
// names and glob patterns are both supported; the most specific matching
// rule wins, otherwise the default limit applies. A repository is
// unrestricted when neither any rule nor a default limit is configured.
type Budgets struct {
	defaultLimit int64
	hasDefault   bool

	// rules sorted by decreasing specificity so the first match wins.
	rules []budgetRule
}

// NewBudgets builds a budget table. defaultSize may be empty (no default
// limit). Repository rules map a glob pattern to a size string parsed by
// ParseSize. Invalid patterns or sizes return an error so misconfiguration
// is surfaced at startup rather than at request time.
func NewBudgets(defaultSize string, repositories map[string]string) (*Budgets, error) {
	b := &Budgets{defaultLimit: Unlimited}

	if defaultSize != "" {
		limit, err := ParseSize(defaultSize)
		if err != nil {
			return nil, fmt.Errorf("accounting: invalid default budget: %w", err)
		}
		b.defaultLimit = limit
		b.hasDefault = true
	}

	for pattern, size := range repositories {
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("accounting: invalid repository budget pattern %q: %w", pattern, err)
		}
		if pattern == "" {
			return nil, fmt.Errorf("accounting: invalid repository budget pattern %q", pattern)
		}
		limit, err := ParseSize(size)
		if err != nil {
			return nil, fmt.Errorf("accounting: invalid budget %q for pattern %q: %w", size, pattern, err)
		}
		b.rules = append(b.rules, budgetRule{pattern: pattern, limit: limit})
	}

	sort.Slice(b.rules, func(i, j int) bool {
		si, sj := specificity(b.rules[i].pattern), specificity(b.rules[j].pattern)
		if si != sj {
			return si > sj
		}
		if len(b.rules[i].pattern) != len(b.rules[j].pattern) {
			return len(b.rules[i].pattern) > len(b.rules[j].pattern)
		}
		return b.rules[i].pattern < b.rules[j].pattern
	})

	return b, nil
}

// Limit returns the configured byte limit for the repository and whether a
// limit applies. A false limited value means the repository is unrestricted.
func (b *Budgets) Limit(repository string) (limit int64, limited bool) {
	if b == nil {
		return Unlimited, false
	}
	for _, rule := range b.rules {
		if matched, err := path.Match(rule.pattern, repository); err == nil && matched {
			return rule.limit, true
		}
	}
	if b.hasDefault {
		return b.defaultLimit, true
	}
	return Unlimited, false
}

// specificity counts literal (non-wildcard) characters in a glob; more
// literals means a more specific rule. Exact names therefore always outrank
// patterns containing wildcards.
func specificity(pattern string) int {
	n := 0
	for _, r := range pattern {
		if r != '*' && r != '?' && r != '[' && r != '\\' {
			n++
		}
	}
	return n
}
