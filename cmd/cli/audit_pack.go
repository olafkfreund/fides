package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"fides/pkg/auditpack"
	"fides/pkg/cosignverify"
	"fides/pkg/exitcode"

	"github.com/google/uuid"
)

func downloadSignedAudit(config CLIConfig, trail, dest string) error {
	id, err := uuid.Parse(trail)
	if err != nil {
		return errors.New("--trail must be a UUID for a signed audit pack")
	}
	req, err := http.NewRequest(http.MethodGet, config.ServerURL+"/api/v1/trails/"+id.String()+"/signed-audit-pack", nil) // #nosec G704 -- operator-configured server
	if err != nil {
		return err
	}
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	resp, err := httpClient.Do(req) // #nosec G704 -- operator-configured server
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}
	headers := resp.Header.Values(auditpack.SignatureHeader)
	if len(headers) != 1 || len(headers[0]) > base64.StdEncoding.EncodedLen(auditpack.MaxSignatureBytes) {
		return errors.New("missing or invalid audit signature header")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(headers[0])
	if err != nil || auditpack.ValidateSignatureFormat(sig) != nil {
		return errors.New("invalid audit signature header")
	}
	if resp.ContentLength > auditpack.MaxArchiveBytes {
		return errors.New("audit pack archive size limit exceeded")
	}

	zipTemp, err := stageAuditFile(dest, resp.Body, auditpack.MaxArchiveBytes)
	if err != nil {
		return fmt.Errorf("stage ZIP: %w", err)
	}
	defer os.Remove(zipTemp)
	sigTemp, err := stageAuditFile(dest, bytes.NewReader(sig), auditpack.MaxSignatureBytes)
	if err != nil {
		return fmt.Errorf("stage signature: %w", err)
	}
	defer os.Remove(sigTemp)

	// Link publishes each completed file without replacing an existing file
	// or following a destination symlink. Publish the ZIP only after its sig.
	sigPath := dest + ".sig"
	if err := os.Link(sigTemp, sigPath); err != nil {
		return fmt.Errorf("publish signature: %w", err)
	}
	if err := os.Link(zipTemp, dest); err != nil {
		return errors.Join(fmt.Errorf("publish ZIP: %w", err), os.Remove(sigPath))
	}
	return nil
}

func stageAuditFile(dest string, source io.Reader, limit int64) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(dest), ".fides-audit-*")
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(source, limit+1))
	if n == 0 || n > limit {
		err = errors.Join(err, errors.New("empty file or audit pack size limit exceeded"))
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return "", errors.Join(err, os.Remove(f.Name()))
	}
	return f.Name(), nil
}

const exitPackIncomplete = 3

func runVerifyPack(out io.Writer, args []string) int {
	cmd := flag.NewFlagSet("verify-pack", flag.ContinueOnError)
	cmd.SetOutput(out)
	var keyPaths []string
	cmd.Func("archive-key", "trusted Ed25519 public key PEM (repeatable)", func(path string) error {
		if path == "" {
			return errors.New("empty archive key path")
		}
		keyPaths = append(keyPaths, path)
		return nil
	})
	rootsPath := cmd.String("tsa-roots", "", "PEM roots for included RFC 3161 timestamp tokens")
	policyPath := cmd.String("signer-policy", "", "local JSON object keyed by artifact SHA-256, with key or trusted_root, signer, and issuer")
	cmd.Usage = func() {
		fmt.Fprintln(out, "Usage: fides verify-pack <pack.zip> --archive-key <public.pem> [--tsa-roots <roots.pem>] [--signer-policy <policy.json>]")
		cmd.PrintDefaults()
		fmt.Fprintln(out, "Exit codes: 0 verified, 1 usage or file error, 2 invalid, 3 incomplete")
	}
	// Accept the archive first as shown in the usage, or after all flags.
	if len(args) > 1 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string(nil), args[1:]...), args[0])
	}
	if err := cmd.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitcode.OK
		}
		return exitcode.Error
	}
	if cmd.NArg() != 1 || len(keyPaths) == 0 {
		cmd.Usage()
		return exitcode.Error
	}
	result, verdict, err := verifyLocalAuditPack(cmd.Arg(0), keyPaths, *rootsPath, *policyPath)
	switch verdict {
	case exitcode.Error:
		fmt.Fprintln(out, err)
	case exitcode.Violation:
		fmt.Fprintf(out, "Invalid audit pack: %v\n", err)
	case exitPackIncomplete:
		fmt.Fprintf(out, "Incomplete audit pack for trail %s\n", result.Manifest.TrailID)
		for _, reason := range result.Incomplete {
			fmt.Fprintf(out, "  %s\n", reason)
		}
	default:
		fmt.Fprintf(out, "Verified audit pack for trail %s (head %s)\n", result.Manifest.TrailID, result.Manifest.ChainHead)
	}
	return verdict
}

func verifyLocalAuditPack(packPath string, keyPaths []string, rootsPath, policyPath string) (auditpack.Result, int, error) {
	var trust auditpack.Trust
	for _, path := range keyPaths {
		key, err := readArchiveKey(path)
		if err != nil {
			return auditpack.Result{}, exitcode.Error, fmt.Errorf("load archive key: %w", err)
		}
		trust.ArchiveKeys = append(trust.ArchiveKeys, key)
	}
	var err error
	if rootsPath != "" {
		data, err := readAuditInput(rootsPath, 4<<20)
		if err != nil {
			return auditpack.Result{}, exitcode.Error, fmt.Errorf("load TSA roots: %w", err)
		}
		trust.TSARoots = x509.NewCertPool()
		if !trust.TSARoots.AppendCertsFromPEM(data) {
			return auditpack.Result{}, exitcode.Error, errors.New("no certificates found in TSA roots")
		}
	}
	if policyPath != "" {
		trust.Signers, err = readSignerPolicy(policyPath)
		if err != nil {
			return auditpack.Result{}, exitcode.Error, fmt.Errorf("load signer policy: %w", err)
		}
	}
	sig, err := readAuditInput(packPath+".sig", auditpack.MaxSignatureBytes)
	if err != nil {
		return auditpack.Result{}, exitcode.Error, fmt.Errorf("read signature: %w", err)
	}
	f, err := openAuditInput(packPath, auditpack.MaxArchiveBytes)
	if err != nil {
		return auditpack.Result{}, exitcode.Error, fmt.Errorf("read archive: %w", err)
	}
	defer f.Close()
	result, err := auditpack.Verify(f, sig, trust)
	if err != nil {
		return result, exitcode.Violation, err
	}
	if len(result.Incomplete) != 0 {
		return result, exitPackIncomplete, nil
	}
	return result, exitcode.OK, nil
}

func readArchiveKey(path string) (ed25519.PublicKey, error) {
	data, err := readAuditInput(path, 4096)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	block, rest := pem.Decode(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PUBLIC KEY-----")) ||
		block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one Ed25519 PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("archive public key must be Ed25519")
	}
	return key, nil
}

// Trust paths in the policy are relative to the policy file if not absolute.
func readSignerPolicy(path string) (map[string]cosignverify.OfflineOptions, error) {
	data, err := readAuditInput(path, 1<<20)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return nil, errors.New("expected a JSON object keyed by artifact SHA-256")
	}
	policy := make(map[string]cosignverify.OfflineOptions)
	for decoder.More() {
		key, err := decoder.Token()
		digest, ok := key.(string)
		raw, hexErr := hex.DecodeString(digest)
		if err != nil || !ok || len(raw) != 32 || hexErr != nil || strings.ToLower(digest) != digest {
			return nil, fmt.Errorf("invalid policy digest %q", digest)
		}
		if _, exists := policy[digest]; exists {
			return nil, fmt.Errorf("duplicate policy for artifact %s", digest)
		}
		var rule struct {
			Key    string `json:"key"`
			Root   string `json:"trusted_root"`
			Signer string `json:"signer"`
			Issuer string `json:"issuer"`
		}
		if err := decoder.Decode(&rule); err != nil {
			return nil, err
		}
		options := cosignverify.OfflineOptions{Digest: digest, Signer: rule.Signer, Issuer: rule.Issuer}
		switch {
		case rule.Key != "" && rule.Root == "" && rule.Signer == "" && rule.Issuer == "":
			options.KeyPath = auditPolicyPath(path, rule.Key)
		case rule.Key == "" && rule.Root != "" && rule.Signer != "" && rule.Issuer != "":
			options.TrustedRootPath = auditPolicyPath(path, rule.Root)
		default:
			return nil, fmt.Errorf("artifact %s requires either a pinned key or a trusted root, signer, and issuer", digest)
		}
		policy[digest] = options
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after signer policy")
	}
	return policy, nil
}

func auditPolicyPath(policyPath, trustPath string) string {
	if filepath.IsAbs(trustPath) {
		return trustPath
	}
	return filepath.Join(filepath.Dir(policyPath), trustPath)
}

func readAuditInput(path string, limit int64) ([]byte, error) {
	f, err := openAuditInput(path, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds size limit: %s", path)
	}
	return data, err
}

func openAuditInput(path string, limit int64) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("expected a regular file within size limit: %s", path)
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied local input
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, fmt.Errorf("file changed while opening: %s", path)
	}
	return f, nil
}
