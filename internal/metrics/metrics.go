// Package metrics renders the daemon's operational metrics in the
// Prometheus text exposition format (version 0.0.4) for GET /admin/metrics.
//
// Labels never carry personal data: their values come from fixed sets (tool
// names, outcomes, connection states, alert kinds, the build version), never
// from JIDs, names, phone numbers or message content.
package metrics

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Label is one name="value" pair.
type Label struct{ Name, Value string }

// Sample is one value of a metric family.
type Sample struct {
	Labels []Label
	Value  float64
}

// Writer accumulates metric families.
type Writer struct{ buf bytes.Buffer }

// Family writes a metric family: HELP, TYPE and its samples. typ is
// "gauge" or "counter".
func (w *Writer) Family(name, help, typ string, samples ...Sample) {
	w.buf.WriteString("# HELP " + name + " " + escapeHelp(help) + "\n")
	w.buf.WriteString("# TYPE " + name + " " + typ + "\n")
	for _, s := range samples {
		w.buf.WriteString(name)
		if len(s.Labels) > 0 {
			w.buf.WriteByte('{')
			for i, l := range s.Labels {
				if i > 0 {
					w.buf.WriteByte(',')
				}
				w.buf.WriteString(l.Name + `="` + escapeLabel(l.Value) + `"`)
			}
			w.buf.WriteByte('}')
		}
		w.buf.WriteString(" " + formatValue(s.Value) + "\n")
	}
}

// Gauge writes a single unlabelled gauge.
func (w *Writer) Gauge(name, help string, v float64) {
	w.Family(name, help, "gauge", Sample{Value: v})
}

// Counter writes a single unlabelled counter.
func (w *Writer) Counter(name, help string, v float64) {
	w.Family(name, help, "counter", Sample{Value: v})
}

// Bytes returns the rendered exposition.
func (w *Writer) Bytes() []byte { return w.buf.Bytes() }

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Bool returns 1 for true and 0 for false.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// LabeledCounter counts events by a fixed tuple of label values.
type LabeledCounter struct {
	mu     sync.Mutex
	names  []string
	counts map[string]uint64
}

// NewLabeledCounter returns a counter whose samples carry the given labels.
func NewLabeledCounter(labelNames ...string) *LabeledCounter {
	return &LabeledCounter{names: labelNames, counts: map[string]uint64{}}
}

// Inc adds one for the given label values (one per label name).
func (c *LabeledCounter) Inc(values ...string) {
	if len(values) != len(c.names) {
		return
	}
	c.mu.Lock()
	c.counts[strings.Join(values, "\x00")]++
	c.mu.Unlock()
}

// Samples returns the counts, sorted by label values.
func (c *LabeledCounter) Samples() []Sample {
	c.mu.Lock()
	keys := make([]string, 0, len(c.counts))
	for k := range c.counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Sample, 0, len(keys))
	for _, k := range keys {
		values := strings.Split(k, "\x00")
		labels := make([]Label, len(c.names))
		for i, n := range c.names {
			labels[i] = Label{Name: n, Value: values[i]}
		}
		out = append(out, Sample{Labels: labels, Value: float64(c.counts[k])})
	}
	c.mu.Unlock()
	return out
}

// Handler serves the exposition that collect writes. Mount it under
// /admin/ so the daemon's bearer-only guard protects it.
func Handler(collect func(ctx context.Context, w *Writer)) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var w Writer
		collect(r.Context(), &w)
		rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		rw.Header().Set("Cache-Control", "no-store")
		_, _ = rw.Write(w.Bytes())
	})
}
