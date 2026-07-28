// Package exitcode defines the process exit codes shared by every fides CLI
// gate command, so CI can tell "policy said no" apart from "the command broke".
//
// The convention (also documented in docs/cli-reference.md):
//
//	0  OK        — success / verified / compliant
//	1  Error     — operational failure: usage, network, parse; the gate never
//	               reached a verdict
//	2  Violation — the gate ran to completion and the verdict is FAIL
//	               (policy/compliance/signature/chain)
//
// Deploy pipelines gate on 2 while still surfacing 1 as a real breakage.
package exitcode

const (
	OK        = 0
	Error     = 1
	Violation = 2
)
