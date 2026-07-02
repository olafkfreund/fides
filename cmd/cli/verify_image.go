package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"fides/pkg/cosignverify"
)

// Exit codes for `fides verify-image`. exitVerifyFailed (2) matches the
// deploy-gate convention used by change-gate/verify-chain/policy check/
// allowlist check (see docs/cli-reference.md); exitError (1) is reserved for
// usage/operational errors that prevented verification from completing.
const (
	exitOK           = 0
	exitError        = 1
	exitVerifyFailed = 2
)

// handleVerifyImage is the `fides verify-image` entrypoint: it verifies a
// container image's cosign signature — keyless via OIDC identity+issuer, or
// key-based via --key — and, when --trail is set, records the verdict as a
// `cosign-verification` attestation. Exits non-zero on any failure to
// complete verification or on a failed/untrusted signature (2), so it can be
// used as a deploy gate.
func handleVerifyImage(config CLIConfig, args []string) {
	os.Exit(runVerifyImage(config, cosignverify.NewSigstoreVerifier(), os.Stdout, args))
}

// runVerifyImage implements `fides verify-image` against an injected
// cosignverify.Verifier (a real SigstoreVerifier in production, a mock in
// tests), returning the process exit code rather than calling os.Exit
// directly so the command is unit-testable.
func runVerifyImage(config CLIConfig, verifier cosignverify.Verifier, out io.Writer, args []string) int {
	cmd := flag.NewFlagSet("verify-image", flag.ContinueOnError)
	cmd.SetOutput(out)
	sha := cmd.String("sha256", "", "Image digest to verify, sha256 hex (required)")
	signer := cmd.String("signer", "", "Expected keyless identity, e.g. an email address or workflow URI SAN")
	issuer := cmd.String("issuer", "", "Expected OIDC issuer, e.g. https://token.actions.githubusercontent.com (optional)")
	key := cmd.String("key", "", "Path to a PEM-encoded public key for key-based verification (skips keyless/OIDC)")
	bundlePath := cmd.String("bundle", "", "Path to a Sigstore/cosign verification bundle (JSON) — see docs/cli-reference.md")
	trail := cmd.String("trail", "", "Trail UUID to record the verdict on as a cosign-verification attestation (optional)")
	name := cmd.String("name", "cosign-verification", "Attestation name")
	if err := cmd.Parse(args); err != nil {
		return exitError
	}

	if *sha == "" || (*signer == "" && *key == "") {
		fmt.Fprintln(out, "Usage: fides verify-image --sha256 <hex> --signer <identity> [--issuer <oidc-issuer>] [--key <pubkey.pem>] [--bundle <path>] [--trail <id>]")
		fmt.Fprintln(out, "Error: --sha256 is required, and either --signer (keyless) or --key (key-based) is required")
		return exitError
	}

	opts := cosignverify.Options{
		Digest:     *sha,
		Signer:     *signer,
		Issuer:     *issuer,
		KeyPath:    *key,
		BundlePath: *bundlePath,
	}

	verdict, err := verifier.Verify(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(out, "Failed to verify image %s: %v\n", *sha, err)
		return exitError
	}

	payload, err := json.Marshal(verdict)
	if err != nil {
		fmt.Fprintf(out, "Failed to encode verdict: %v\n", err)
		return exitError
	}

	if *trail != "" {
		respBody, uerr := uploadMultipart(config, *trail, *sha, *name, "cosign-verification", string(payload), nil, false)
		if uerr != nil {
			fmt.Fprintf(out, "Verification completed (verified=%v) but failed to record attestation: %v\n", verdict.Verified, uerr)
			if !verdict.Verified {
				return exitVerifyFailed
			}
			return exitError
		}
		fmt.Fprintf(out, "Recorded cosign-verification attestation: %s\n", respBody)
	}

	if !verdict.Verified {
		fmt.Fprintf(out, "COSIGN VERIFICATION FAILED for %s: %s\n", *sha, verdict.Reason)
		return exitVerifyFailed
	}

	fmt.Fprintf(out, "COSIGN VERIFICATION PASSED for %s (method=%s signer=%s issuer=%s)\n", *sha, verdict.Method, verdict.Signer, verdict.Issuer)
	return exitOK
}
