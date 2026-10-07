// Package accounting implements a per-repository usage ledger for the
// registry. Repository logical usage is tracked independently of physical
// storage: a blob mounted into several repositories is counted once against
// each referencing repository while the blob data itself stays deduplicated
// in the global blob store.
//
// The ledger is an append-only event log stored through the registry storage
// driver. All state changes are immutable, idempotent events; current state
// is reconstructed by replaying events (optionally over a compacted
// snapshot). This makes retries, crashes and multi-replica concurrency safe
// without requiring any driver-native compare-and-swap support.
package accounting

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseSize parses a byte size specification such as "10GiB", "512MB" or
// "1024". A bare number is interpreted as bytes. Binary suffixes (KiB, MiB,
// GiB, TiB, PiB) use powers of 1024; decimal suffixes (KB, MB, GB, TB, PB)
// use powers of 1000. The suffix is case-insensitive and surrounding
// whitespace is allowed. A zero size is valid and means "no writes allowed".
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size specification")
	}

	// split into numeric prefix and unit suffix.
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	numPart, unitPart := s[:i], strings.TrimSpace(s[i:])
	if numPart == "" {
		return 0, fmt.Errorf("invalid size specification %q: missing number", s)
	}
	if i < len(s) && unitPart == "" {
		// trailing whitespace was inside the numeric range already handled;
		// any other non-digit non-unit content ends up here as a bad unit.
		return 0, fmt.Errorf("invalid size specification %q", s)
	}

	value, err := strconv.ParseInt(numPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size specification %q: %w", s, err)
	}

	if unitPart == "" {
		return value, nil
	}

	multiplier, ok := sizeUnits[strings.ToLower(unitPart)]
	if !ok {
		return 0, fmt.Errorf("invalid size specification %q: unknown unit %q", s, unitPart)
	}
	if value != 0 && value > (1<<63-1)/multiplier {
		return 0, fmt.Errorf("size specification %q overflows int64", s)
	}
	return value * multiplier, nil
}

var sizeUnits = map[string]int64{
	"b": 1,

	"kb": 1000,
	"mb": 1000 * 1000,
	"gb": 1000 * 1000 * 1000,
	"tb": 1000 * 1000 * 1000 * 1000,
	"pb": 1000 * 1000 * 1000 * 1000 * 1000,

	"kib": 1 << 10,
	"mib": 1 << 20,
	"gib": 1 << 30,
	"tib": 1 << 40,
	"pib": 1 << 50,

	// Common spellings without the trailing "b".
	"k":  1 << 10,
	"ki": 1 << 10,
	"m":  1 << 20,
	"mi": 1 << 20,
	"g":  1 << 30,
	"gi": 1 << 30,
	"t":  1 << 40,
	"ti": 1 << 40,
}
