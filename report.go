package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity ranks a finding. Higher is worse.
type Severity int

const (
	SevMedium Severity = iota + 1
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "critical"
	case SevHigh:
		return "high"
	case SevMedium:
		return "medium"
	}
	return "unknown"
}

// parseSeverity reads a --fail-on value.
func parseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical, true
	case "high":
		return SevHigh, true
	case "medium":
		return SevMedium, true
	}
	return 0, false
}

// Finding is one rule hit.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"-"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Resource string   `json:"resource"`
	Message  string   `json:"message"`
}

// findingJSON is the wire form of a finding (severity as a word).
type findingJSON struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
}

// Report is the full scan result.
type Report struct {
	Path         string
	FilesScanned int
	Findings     []Finding
}

// sortFindings orders findings by severity (worst first), then file,
// then line. It is a pure function of the slice contents.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// counts returns (critical, high, medium) totals.
func (r Report) counts() (int, int, int) {
	var c, h, m int
	for _, f := range r.Findings {
		switch f.Severity {
		case SevCritical:
			c++
		case SevHigh:
			h++
		case SevMedium:
			m++
		}
	}
	return c, h, m
}

// anyAtOrAbove reports whether any finding meets the fail threshold.
func (r Report) anyAtOrAbove(threshold Severity) bool {
	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}

// renderText renders the grouped, plain-language report.
func (r Report) renderText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tf-check: scanned %d file(s) under %s\n", r.FilesScanned, r.Path)
	if len(r.Findings) == 0 {
		b.WriteString("\nNo findings. Nothing in the scanned files matched the rules.\n")
		return b.String()
	}
	for _, sev := range []Severity{SevCritical, SevHigh, SevMedium} {
		var group []Finding
		for _, f := range r.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d)\n", strings.ToUpper(sev.String()), len(group))
		for _, f := range group {
			fmt.Fprintf(&b, "  %s  %s:%d  %s\n", f.Rule, f.File, f.Line, f.Resource)
			fmt.Fprintf(&b, "    %s\n", f.Message)
		}
	}
	c, h, m := r.counts()
	fmt.Fprintf(&b, "\nSummary: %d critical, %d high, %d medium across %d file(s).\n", c, h, m, r.FilesScanned)
	return b.String()
}

// renderJSON renders the report as indented JSON.
func (r Report) renderJSON() (string, error) {
	c, h, m := r.counts()
	wire := struct {
		Path         string         `json:"path"`
		FilesScanned int            `json:"files_scanned"`
		Summary      map[string]int `json:"summary"`
		Findings     []findingJSON  `json:"findings"`
	}{
		Path:         r.Path,
		FilesScanned: r.FilesScanned,
		Summary:      map[string]int{"critical": c, "high": h, "medium": m},
		Findings:     make([]findingJSON, 0, len(r.Findings)),
	}
	for _, f := range r.Findings {
		wire.Findings = append(wire.Findings, findingJSON{
			Rule:     f.Rule,
			Severity: f.Severity.String(),
			File:     f.File,
			Line:     f.Line,
			Resource: f.Resource,
			Message:  f.Message,
		})
	}
	data, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}
