package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{Rule: "A", Severity: SevMedium, File: "a.tf", Line: 1},
		{Rule: "B", Severity: SevCritical, File: "b.tf", Line: 9},
		{Rule: "C", Severity: SevCritical, File: "a.tf", Line: 30},
		{Rule: "D", Severity: SevCritical, File: "a.tf", Line: 3},
		{Rule: "E", Severity: SevHigh, File: "a.tf", Line: 1},
	}
	sortFindings(fs)
	want := []string{"D", "C", "B", "E", "A"} // severity desc, file asc, line asc
	for i, id := range want {
		if fs[i].Rule != id {
			t.Fatalf("position %d = %s, want %s (full order: %+v)", i, fs[i].Rule, id, fs)
		}
	}
}

func TestFailOnMapping(t *testing.T) {
	rep := Report{Findings: []Finding{{Severity: SevHigh}}}
	if rep.anyAtOrAbove(SevCritical) {
		t.Error("a high finding must not trip the critical threshold")
	}
	if !rep.anyAtOrAbove(SevHigh) || !rep.anyAtOrAbove(SevMedium) {
		t.Error("a high finding must trip high and medium thresholds")
	}
	if (Report{}).anyAtOrAbove(SevMedium) {
		t.Error("an empty report must not trip any threshold")
	}
	for s, want := range map[string]Severity{"critical": SevCritical, "high": SevHigh, "medium": SevMedium, "HIGH": SevHigh} {
		if got, ok := parseSeverity(s); !ok || got != want {
			t.Errorf("parseSeverity(%q) = %v,%v; want %v,true", s, got, ok, want)
		}
	}
	if _, ok := parseSeverity("whenever"); ok {
		t.Error("parseSeverity accepted a bad value")
	}
}

// runCmdFor executes the root command against args and reports the
// mapped exit code plus captured stdout.
func runCmdFor(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(args)
	_, err := cmd.ExecuteC()
	return exitCodeFor(err), buf.String()
}

func writeTF(t *testing.T, dir, name, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCLIExitCodes(t *testing.T) {
	risky := t.TempDir()
	writeTF(t, risky, "main.tf", `resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = true
}
`)

	clean := t.TempDir()
	writeTF(t, clean, "main.tf", `resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
}
`)

	empty := t.TempDir()

	if code, _ := runCmdFor(t, "--path", risky); code != 1 {
		t.Errorf("risky dir exit = %d, want 1 (critical finding, default fail-on)", code)
	}
	if code, _ := runCmdFor(t, "--path", risky, "--fail-on", "medium"); code != 1 {
		t.Errorf("risky dir fail-on=medium exit = %d, want 1", code)
	}
	if code, _ := runCmdFor(t, "--path", clean); code != 0 {
		t.Errorf("clean dir exit = %d, want 0", code)
	}
	if code, _ := runCmdFor(t, "--path", empty); code != 2 {
		t.Errorf("empty dir exit = %d, want 2 (nothing to scan)", code)
	}
	if code, _ := runCmdFor(t, "--path", clean, "--fail-on", "bogus"); code != 2 {
		t.Errorf("bad --fail-on exit = %d, want 2", code)
	}
	if code, _ := runCmdFor(t, "--path", filepath.Join(empty, "missing")); code != 2 {
		t.Errorf("missing path exit = %d, want 2", code)
	}
}

func TestCLIJSONOutputIsValid(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `resource "aws_db_instance" "db" {
  publicly_accessible = true
}
`)
	code, out := runCmdFor(t, "--path", dir, "--json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var decoded struct {
		FilesScanned int `json:"files_scanned"`
		Summary      map[string]int
		Findings     []struct {
			Rule     string
			Severity string
		}
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if decoded.FilesScanned != 1 || decoded.Summary["critical"] != 1 {
		t.Errorf("decoded = %+v, want 1 file and 1 critical", decoded)
	}
	found := false
	for _, f := range decoded.Findings {
		if f.Rule == "PUBLIC-DATABASE" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Errorf("findings missing PUBLIC-DATABASE critical: %+v", decoded.Findings)
	}
	if strings.Contains(out, "\n\n") && !strings.Contains(out, "findings") {
		t.Error("suspicious JSON output")
	}
}
