package ai

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type modelTransport func(*http.Request) (*http.Response, error)

func (f modelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestEvaluateAttestationOutboundEndpoints(t *testing.T) {
	const ollamaEndpoint = "http://10.0.0.30:11434"
	const llamaEndpoint = "http://10.0.0.40:8080"
	const completion = "COMPLIANCE_SCORE: 78"
	ollama := NewOllamaClient(ollamaEndpoint, "test-model")
	llama := NewLlamaCppClient(llamaEndpoint)
	gemini := NewGeminiClient("test-key", "test-model")

	for _, tc := range []struct {
		name     string
		model    LLMClient
		client   *http.Client
		url      string
		apiKey   string
		response string
	}{
		{"Ollama", ollama, ollama.Client, ollamaEndpoint + "/api/generate", "",
			`{"response":"COMPLIANCE_SCORE: 78"}`},
		{"llama.cpp", llama, llama.Client, llamaEndpoint + "/completion", "",
			`{"content":"COMPLIANCE_SCORE: 78"}`},
		{"Gemini", gemini, gemini.Client, "https://generativelanguage.googleapis.com/v1beta/models/test-model:generateContent", "test-key",
			`{"candidates":[{"content":{"parts":[{"text":"COMPLIANCE_SCORE: 78"}]}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.client.Transport = modelTransport(func(req *http.Request) (*http.Response, error) {
				defer req.Body.Close()
				if req.Method != http.MethodPost || req.URL.String() != tc.url {
					t.Errorf("request = %s %s, want POST %s", req.Method, req.URL, tc.url)
				}
				if key := req.Header.Get("X-Goog-Api-Key"); key != tc.apiKey {
					t.Errorf("X-Goog-Api-Key = %q, want %q", key, tc.apiKey)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(tc.response)),
				}, nil
			})
			got, score, err := tc.model.EvaluateAttestation(t.Context(), "test-attestation", "text/plain", "test evidence")
			if err != nil || got != completion || score != 78 {
				t.Fatalf("EvaluateAttestation = (%q, %d, %v), want (%q, 78, nil)", got, score, err, completion)
			}
		})
	}
}
