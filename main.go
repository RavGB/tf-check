// Command tf-check is a quick first-pass scan of Terraform files for
// common safety and cost risks, in plain words.
//
// It reads blocks and attributes as text; it does not evaluate
// Terraform, and it is not a replacement for a real review.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// exitError carries a process exit code with no message: the report
// has already been printed by the time it is returned.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// usageError is a problem with how the tool was invoked (bad flag
// value, nothing to scan). It exits 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

type options struct {
	path   string
	failOn string
	json   bool
	output string
}

func newRootCmd() *cobra.Command {
	var opts options
	cmd := &cobra.Command{
		Use:   "tf-check",
		Short: "Scan Terraform files for common safety and cost risks",
		Long: `tf-check is a quick first-pass scan of Terraform files for common
safety and cost risks, explained in plain words: security groups open
to the whole internet, public storage buckets, databases anyone can
reach, secrets written into the code, and overly broad IAM policies.

It reads blocks and attributes as text. It does not evaluate
Terraform, so it cannot see values built by functions, variables, or
loops. Treat a clean result as "nothing common was spotted", never
as proof that a setup is safe, and always follow up with a real
review before relying on these files.

Exit codes: 0 = no findings at or above --fail-on, 1 = findings at
or above --fail-on, 2 = usage error or nothing to scan.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		// SilenceUsage matters beyond tidiness: a run that finds a
		// critical issue exits 1 via an error, and usage text printed
		// after the report would corrupt --json output on stdout.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", ".", "directory to scan for .tf files")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "critical", "lowest severity that fails the run: critical, high, or medium")
	cmd.Flags().BoolVar(&opts.json, "json", false, "print the report as JSON")
	cmd.Flags().StringVar(&opts.output, "output", "", "also write the report to this file")
	return cmd
}

func runScan(cmd *cobra.Command, opts options) error {
	threshold, ok := parseSeverity(opts.failOn)
	if !ok {
		return &usageError{msg: fmt.Sprintf("invalid --fail-on value %q: use critical, high, or medium", opts.failOn)}
	}

	files, err := findTFFiles(opts.path)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	if len(files) == 0 {
		return &usageError{msg: fmt.Sprintf("no .tf files found under %s", opts.path)}
	}

	project, err := scanFiles(files)
	if err != nil {
		return err
	}

	report := Report{Path: opts.path, FilesScanned: len(files), Findings: runRules(project)}
	sortFindings(report.Findings)

	var rendered string
	if opts.json {
		rendered, err = report.renderJSON()
		if err != nil {
			return err
		}
	} else {
		rendered = report.renderText()
	}
	fmt.Fprint(cmd.OutOrStdout(), rendered)

	if opts.output != "" {
		if err := os.WriteFile(opts.output, []byte(rendered), 0o644); err != nil {
			return fmt.Errorf("writing report to %s: %w", opts.output, err)
		}
	}

	if report.anyAtOrAbove(threshold) {
		return &exitError{code: 1}
	}
	return nil
}

// findTFFiles walks root for .tf files, skipping version-control and
// Terraform working directories (vendored modules are not the user's
// own code to fix). Paths come back in sorted order.
func findTFFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", root, err)
	}
	if info.Mode().IsRegular() && strings.HasSuffix(root, ".tf") {
		return []string{root}, nil
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".tf") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func scanFiles(paths []string) (*Project, error) {
	project := &Project{}
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		doc, blocks := parseFile(path, string(data), i)
		project.Files = append(project.Files, doc)
		project.Blocks = append(project.Blocks, blocks...)
	}
	return project, nil
}

// exitCodeFor maps a command error to a process exit code.
func exitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	var ue *usageError
	if errors.As(err, &ue) {
		return 2
	}
	return 2
}

func runCLI() int {
	cmd := newRootCmd()
	_, err := cmd.ExecuteC()
	if err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			return ee.code // report already printed; nothing more to say
		}
		fmt.Fprintln(os.Stderr, "tf-check:", err)
		return exitCodeFor(err)
	}
	return 0
}

func main() {
	os.Exit(runCLI())
}
