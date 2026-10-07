package accounting

import (
	regmetrics "github.com/distribution/distribution/v3/metrics"
	gometrics "github.com/docker/go-metrics"
	stdprom "github.com/prometheus/client_golang/prometheus"
)

// Metric names (registry_accounting_*):
//
//	repository_settled_bytes   gauge  per repository settled usage
//	repository_reserved_bytes  gauge  per repository active reservations
//	repository_budget_bytes    gauge  per repository budget (-1 if unlimited)
//	repository_available_bytes gauge  per repository remaining budget
//	quota_denied_total         counter per repository and request phase

// promSink adapts ledger changes to Prometheus metrics.
type promSink struct {
	settled   *stdprom.GaugeVec
	reserved  *stdprom.GaugeVec
	budget    *stdprom.GaugeVec
	available *stdprom.GaugeVec
	denied    *stdprom.CounterVec
}

func newPromSink() *promSink {
	ns := regmetrics.AccountingNamespace
	sink := &promSink{
		settled: stdprom.NewGaugeVec(stdprom.GaugeOpts{
			Namespace: regmetrics.NamespacePrefix,
			Subsystem: "accounting",
			Name:      "repository_settled_bytes",
			Help:      "Settled storage usage in bytes attributed to the repository (shared blobs counted per referencing repository).",
		}, []string{"repository"}),
		reserved: stdprom.NewGaugeVec(stdprom.GaugeOpts{
			Namespace: regmetrics.NamespacePrefix,
			Subsystem: "accounting",
			Name:      "repository_reserved_bytes",
			Help:      "Bytes reserved by in-flight pushes and mounts in the repository.",
		}, []string{"repository"}),
		budget: stdprom.NewGaugeVec(stdprom.GaugeOpts{
			Namespace: regmetrics.NamespacePrefix,
			Subsystem: "accounting",
			Name:      "repository_budget_bytes",
			Help:      "Configured byte budget of the repository (-1 when unlimited).",
		}, []string{"repository"}),
		available: stdprom.NewGaugeVec(stdprom.GaugeOpts{
			Namespace: regmetrics.NamespacePrefix,
			Subsystem: "accounting",
			Name:      "repository_available_bytes",
			Help:      "Bytes still available in the repository budget (-1 when unlimited).",
		}, []string{"repository"}),
		denied: stdprom.NewCounterVec(stdprom.CounterOpts{
			Namespace: regmetrics.NamespacePrefix,
			Subsystem: "accounting",
			Name:      "quota_denied_total",
			Help:      "Total number of requests denied for exceeding the repository budget, by phase.",
		}, []string{"repository", "phase"}),
	}
	ns.Add(sink.settled)
	ns.Add(sink.reserved)
	ns.Add(sink.budget)
	ns.Add(sink.available)
	ns.Add(sink.denied)
	return sink
}

func (p *promSink) Observe(repo string, settled, reserved, limit int64) {
	p.settled.WithLabelValues(repo).Set(float64(settled))
	p.reserved.WithLabelValues(repo).Set(float64(reserved))
	p.budget.WithLabelValues(repo).Set(float64(limit))
	available := limit
	if limit != Unlimited {
		available = limit - settled - reserved
	}
	p.available.WithLabelValues(repo).Set(float64(available))
}

func (p *promSink) Denied(repo string, phase Phase) {
	p.denied.WithLabelValues(repo, string(phase)).Inc()
}

func (p *promSink) Forget(repo string) {
	p.settled.DeleteLabelValues(repo)
	p.reserved.DeleteLabelValues(repo)
	p.budget.DeleteLabelValues(repo)
	p.available.DeleteLabelValues(repo)
	// counter values are cumulative; only the gauge series are removed.
}

var defaultSink Sink = newPromSink()

func init() {
	// Register alongside the other registry namespaces.
	gometrics.Register(regmetrics.AccountingNamespace)
}
