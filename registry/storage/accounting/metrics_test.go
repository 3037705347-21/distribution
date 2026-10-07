package accounting

import (
	"testing"

	stdprom "github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func gaugeValue(t *testing.T, g interface {
	Write(*dto.Metric) error
}) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := g.Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetGauge().GetValue()
}

func counterValue(t *testing.T, c interface {
	Write(*dto.Metric) error
}) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestPromSinkObserveDenyForget(t *testing.T) {
	s := newPromSink()
	const repo = "team-a/app"

	s.Observe(repo, 700, 300, 1000)
	if got := gaugeValue(t, s.settled.WithLabelValues(repo)); got != 700 {
		t.Errorf("settled gauge = %v", got)
	}
	if got := gaugeValue(t, s.reserved.WithLabelValues(repo)); got != 300 {
		t.Errorf("reserved gauge = %v", got)
	}
	if got := gaugeValue(t, s.budget.WithLabelValues(repo)); got != 1000 {
		t.Errorf("budget gauge = %v", got)
	}
	if got := gaugeValue(t, s.available.WithLabelValues(repo)); got != 0 {
		t.Errorf("available gauge = %v", got)
	}

	s.Observe(repo, 700, 0, 1000)
	if got := gaugeValue(t, s.available.WithLabelValues(repo)); got != 300 {
		t.Errorf("available after settle = %v", got)
	}

	// unlimited repo gets -1 limit/available.
	const repo2 = "team-b/app"
	s.Observe(repo2, 10, 5, Unlimited)
	if got := gaugeValue(t, s.budget.WithLabelValues(repo2)); got != -1 {
		t.Errorf("unlimited budget gauge = %v", got)
	}
	if got := gaugeValue(t, s.available.WithLabelValues(repo2)); got != -1 {
		t.Errorf("unlimited available gauge = %v", got)
	}

	s.Denied(repo, PhaseMount)
	s.Denied(repo, PhaseMount)
	if got := counterValue(t, s.denied.WithLabelValues(repo, string(PhaseMount))); got != 2 {
		t.Errorf("denied counter = %v, want 2", got)
	}

	// Forget drops the gauge series; the cumulative counter survives.
	s.Forget(repo)
	if n := collectCount(s.settled); n != 1 {
		t.Errorf("settled series after forget = %d, want 1 (repo2 remains)", n)
	}
	if got := counterValue(t, s.denied.WithLabelValues(repo, string(PhaseMount))); got != 2 {
		t.Errorf("denied counter after forget = %v, want 2", got)
	}
}

// collectCount gathers all current child series of a collector.
func collectCount(c stdprom.Collector) int {
	ch := make(chan stdprom.Metric, 32)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	n := 0
	for range ch {
		n++
	}
	return n
}
