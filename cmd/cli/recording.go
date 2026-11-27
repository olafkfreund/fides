package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	trailRecord       = "/api/v1/trails"
	artifactRecord    = "/api/v1/artifacts"
	attestationRecord = "/api/v1/attestations"
	offlinePrefix     = "offline:"
	maxRecordingBody  = 64 << 20 // Matches the server request body limit.
)

type recording struct {
	Key            uuid.UUID
	Path           string
	ContentType    string
	Binding        string
	TrailRef       uuid.UUID
	TrailOffset    int
	ArtifactSHA    string
	ConfirmedTrail uuid.UUID
}

func recordingFlag(cmd *flag.FlagSet, config *CLIConfig) {
	enabled, _ := strconv.ParseBool(os.Getenv("FIDES_FAIL_OPEN"))
	cmd.BoolVar(&config.FailOpen, "fail-open", enabled, "Queue evidence locally when Fides is temporarily unavailable")
}

func validRecordingUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil
}

func recordJSON(config CLIConfig, path string, payload map[string]any, trailID string) (string, error) {
	entry := recording{Path: path, ContentType: "application/json"}
	if config.FailOpen {
		if path == trailRecord {
			flowID, _ := payload["flow_id"].(string)
			if !validRecordingUUID(flowID) {
				return "", errors.New("invalid flow UUID")
			}
		} else if digest, _ := payload["sha256"].(string); !isSHA256Hex(digest) {
			return "", errors.New("invalid artifact SHA256")
		}
		limits := map[string]int{"name": 100, "git_repository": 255, "git_commit": 40, "git_branch": 100}
		if path == artifactRecord {
			limits = map[string]int{"name": 255, "type": 50}
		}
		for field, limit := range limits {
			if value, _ := payload[field].(string); utf8.RuneCountInString(value) > limit {
				return "", fmt.Errorf("%s exceeds %d characters", field, limit)
			}
		}
	}
	if path == artifactRecord {
		entry.ArtifactSHA, _ = payload["sha256"].(string)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return record(config, entry, body, trailID)
}

// Recording accepts only a fixed endpoint and binds the queue to the exact
// configured credential. An opaque service token has no offline tenant identity.
func recordingEndpoint(config CLIConfig) (string, string, error) {
	base := strings.TrimRight(config.ServerURL, "/")
	endpoint, err := url.Parse(base)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") ||
		endpoint.Hostname() == "" || endpoint.User != nil || endpoint.ForceQuery ||
		strings.Contains(base, "#") || endpoint.RawQuery != "" {
		return "", "", errors.New("invalid FIDES_SERVER_URL for recording")
	}
	if port := endpoint.Port(); port != "" {
		if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
			return "", "", errors.New("invalid FIDES_SERVER_URL port")
		}
	} else if strings.HasSuffix(endpoint.Host, ":") {
		return "", "", errors.New("invalid FIDES_SERVER_URL port")
	}
	if config.Token == "" || strings.ContainsFunc(config.Token, func(r rune) bool { return r <= ' ' || r >= 127 }) {
		return "", "", errors.New("a valid FIDES_API_TOKEN is required for the recording queue")
	}
	digest := sha256.Sum256([]byte("fides-recording-v1\x00" + base + "\x00" + config.Token))
	return base, fmt.Sprintf("%x", digest), nil
}

func record(config CLIConfig, entry recording, body []byte, trailID string) (string, error) {
	base := config.ServerURL
	if !config.FailOpen && !strings.HasPrefix(trailID, offlinePrefix) {
		response, _, _, err := sendRecording(config, base, entry, body)
		return response, err
	}
	entry.Key = uuid.New()
	if len(body) > maxRecordingBody {
		return "", errors.New("recording body exceeds the server size limit")
	}
	if ref, ok := strings.CutPrefix(trailID, offlinePrefix); ok {
		id, err := uuid.Parse(ref)
		if err != nil || id == uuid.Nil || id.String() != ref {
			return "", errors.New("invalid offline trail reference")
		}
		entry.TrailRef = id
	} else if trailID != "" && !validRecordingUUID(trailID) {
		return "", errors.New("invalid trail UUID")
	}
	base, binding, err := recordingEndpoint(config)
	if err != nil {
		return "", err
	}
	entry.Binding = binding

	var spool *os.File
	if entry.TrailRef != uuid.Nil || (config.FailOpen && entry.Path == attestationRecord && entry.ArtifactSHA != "") {
		spool, err = openRecordingSpool(false)
		if err != nil {
			return "", err
		}
		if spool != nil {
			defer spool.Close()
		}
	}

	requestBody := body
	if entry.TrailRef != uuid.Nil {
		if spool == nil {
			return "", fmt.Errorf("unknown offline trail %s", trailID)
		}
		resolved, err := resolveRecordingTrail(spool, entry)
		if err != nil {
			return "", err
		}
		if resolved == uuid.Nil {
			if !config.FailOpen {
				return "", fmt.Errorf("offline trail %s is pending replay", trailID)
			}
			return queueRecording(spool, entry, body, "offline trail is pending replay")
		}
		requestBody, err = entry.withTrail(body, resolved)
		if err != nil {
			return "", err
		}
	}
	if spool != nil && config.FailOpen && entry.Path == attestationRecord && entry.ArtifactSHA != "" {
		entries, err := listRecordings(spool)
		if err != nil {
			return "", err
		}
		for _, pending := range entries {
			if pending.Binding == entry.Binding && pending.Path == artifactRecord && pending.ArtifactSHA == entry.ArtifactSHA {
				return queueRecording(spool, entry, body, "artifact is pending replay")
			}
		}
	}

	response, status, retryable, err := sendRecording(config, base, entry, requestBody)
	if err == nil && config.FailOpen {
		_, err = entry.confirmedID(response, status)
	}
	if !retryable || !config.FailOpen {
		return response, err
	}
	if spool == nil {
		spool, err = openRecordingSpool(true)
		if err != nil {
			return "", err
		}
		defer spool.Close()
	}
	return queueRecording(spool, entry, body, "Fides is temporarily unavailable")
}

func (entry recording) withTrail(body []byte, trail uuid.UUID) ([]byte, error) {
	old := []byte(offlinePrefix + entry.TrailRef.String())
	offset := entry.TrailOffset
	if entry.Path == artifactRecord {
		field := []byte(`"trail_id":"`)
		offset = bytes.Index(body, append(append([]byte{}, field...), old...))
		if offset < 0 {
			return nil, errors.New("missing artifact trail dependency")
		}
		offset += len(field)
	}
	if offset < 0 || offset > len(body) || !bytes.HasPrefix(body[offset:], old) {
		return nil, errors.New("invalid recording trail dependency")
	}
	resolved := make([]byte, 0, len(body)-len(offlinePrefix))
	resolved = append(resolved, body[:offset]...)
	resolved = append(resolved, trail.String()...)
	return append(resolved, body[offset+len(old):]...), nil
}

func sendRecording(config CLIConfig, base string, entry recording, body []byte) (string, int, bool, error) {
	req, err := http.NewRequest(http.MethodPost, base+entry.Path, bytes.NewReader(body)) // #nosec G704 -- uses the operator-configured, bound Fides endpoint
	if err != nil {
		return "", 0, false, err
	}
	req.Header.Set("Content-Type", entry.ContentType)
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	client := *httpClient
	if entry.Key != uuid.Nil {
		req.Header.Set("Idempotency-Key", entry.Key.String())
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	resp, err := client.Do(req) // #nosec G704 -- uses the operator-configured Fides endpoint
	if err != nil {
		return "", 0, recordingTransportError(err), err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 || (entry.Key != uuid.Nil && (resp.StatusCode < 200 || resp.StatusCode >= 300)) {
		retryable := err == nil && resp.Header.Get("WWW-Authenticate") == "" && resp.Header.Get("Proxy-Authenticate") == "" &&
			retryableRecordingStatus(resp.StatusCode, strings.TrimSpace(string(data)))
		return "", resp.StatusCode, retryable, fmt.Errorf("server returned error code: %d, body: %s", resp.StatusCode, data)
	}
	if err != nil {
		return "", resp.StatusCode, recordingTransportError(err), err
	}
	return string(data), resp.StatusCode, false, nil
}

func retryableRecordingStatus(status int, body string) bool {
	switch status {
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return true
	case http.StatusServiceUnavailable:
		switch body {
		case "API authentication is not configured on the server",
			"service token tenant (FIDES_API_ORG_ID) is not configured",
			"portal tenant (FIDES_API_ORG_ID) is not configured":
			return false
		}
		return true
	}
	return false
}

func recordingTransportError(err error) bool {
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return !dns.IsNotFound && (dns.IsTimeout || dns.IsTemporary)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
}
