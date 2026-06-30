package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLMClient interface {
	EvaluateAttestation(ctx context.Context, attestationName, payloadType, payloadData string) (string, int, error)
	GeneratePolicy(ctx context.Context, framework, description string) (string, error)
	Chat(ctx context.Context, history []ChatMessage, message string) (string, error)
}

// OllamaClient connects to a local Ollama daemon
type OllamaClient struct {
	Endpoint string
	Model    string
	Client   *http.Client
}

func NewOllamaClient(endpoint, model string) *OllamaClient {
	return &OllamaClient{
		Endpoint: endpoint,
		Model:    model,
		Client:   &http.Client{Timeout: 60 * time.Second},
	}
}

type ollamaReq struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResp struct {
	Response string `json:"response"`
}

func (c *OllamaClient) EvaluateAttestation(ctx context.Context, attestationName, payloadType, payloadData string) (string, int, error) {
	prompt := fmt.Sprintf(`Analyze the following software build attestation evidence:
Attestation Name: %s
Payload Type: %s
Payload Data:
%s

You are a security and compliance auditor. Review the payload data above. Perform the following checks:
1. Identify any critical or high vulnerabilities, failing test cases, or licensing risks.
2. Confirm if the payload is compliant.
3. Output your assessment in markdown. Explain your reasoning.
4. Conclude with a compliance score between 0 (completely failed/unsafe) and 100 (fully compliant/safe) in this exact format:
COMPLIANCE_SCORE: <score>`, attestationName, payloadType, payloadData)

	reqBody, err := json.Marshal(ollamaReq{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to call Ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("ollama returned non-200 status: %d", resp.StatusCode)
	}

	var parsed ollamaResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", 0, err
	}

	score := extractScore(parsed.Response)
	return parsed.Response, score, nil
}

func (c *OllamaClient) GeneratePolicy(ctx context.Context, framework, description string) (string, error) {
	prompt := fmt.Sprintf(`You are a DevSecOps compliance officer. Generate a Fides validation policy rule in JSON format.
The policy should target compliance framework: "%s".
Description/Requirements: "%s".

Your output MUST be a valid JSON object matching the following structure:
{
  "name": "policy-name",
  "description": "Short description of what the policy verifies",
  "rules": {
    "controls": [
      {
        "name": "control-name",
        "attestation_type": "type-of-attestation (e.g. sbom, snyk-scan, unit-tests)",
        "jq_expressions": [
          "JQ rule expression returning boolean (e.g. .vulnerabilities[] | select(.severity == \\\"CRITICAL\\\") | length == 0)"
        ]
      }
    ]
  }
}
Output only the JSON block. Do not include any other markdown text.`, framework, description)

	reqBody, err := json.Marshal(ollamaReq{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama non-200: %d", resp.StatusCode)
	}

	var parsed ollamaResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	return parsed.Response, nil
}

func (c *OllamaClient) Chat(ctx context.Context, history []ChatMessage, message string) (string, error) {
	var promptBuilder bytes.Buffer
	promptBuilder.WriteString("You are Fides, a multi-tenant compliance and supply chain audit assistant. You help manage flows, trails, and audit logs.\n")
	promptBuilder.WriteString("Here is the chat history:\n")
	for _, msg := range history {
		promptBuilder.WriteString(fmt.Sprintf("%s: %s\n", msg.Role, msg.Content))
	}
	promptBuilder.WriteString(fmt.Sprintf("User: %s\n", message))
	promptBuilder.WriteString("Response:")

	reqBody, err := json.Marshal(ollamaReq{
		Model:  c.Model,
		Prompt: promptBuilder.String(),
		Stream: false,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama non-200: %d", resp.StatusCode)
	}

	var parsed ollamaResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	return parsed.Response, nil
}

// LlamaCppClient connects to a local llama.cpp /v1/completions server
type LlamaCppClient struct {
	Endpoint string
	Client   *http.Client
}

func NewLlamaCppClient(endpoint string) *LlamaCppClient {
	return &LlamaCppClient{
		Endpoint: endpoint,
		Client:   &http.Client{Timeout: 60 * time.Second},
	}
}

type llamaCppReq struct {
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type llamaCppResp struct {
	Content string `json:"content"` // Standard response in llama.cpp simple completion API
}

func (c *LlamaCppClient) EvaluateAttestation(ctx context.Context, attestationName, payloadType, payloadData string) (string, int, error) {
	prompt := fmt.Sprintf(`Analyze the following software build attestation evidence:
Attestation Name: %s
Payload Type: %s
Payload Data:
%s

You are a security and compliance auditor. Review the payload data above. Perform the following checks:
1. Identify any critical or high vulnerabilities, failing test cases, or licensing risks.
2. Confirm if the payload is compliant.
3. Output your assessment in markdown. Explain your reasoning.
4. Conclude with a compliance score between 0 (completely failed/unsafe) and 100 (fully compliant/safe) in this exact format:
COMPLIANCE_SCORE: <score>`, attestationName, payloadType, payloadData)

	reqBody, err := json.Marshal(llamaCppReq{
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/completion", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to call llama.cpp: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("llama.cpp returned non-200 status: %d", resp.StatusCode)
	}

	var parsed llamaCppResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", 0, err
	}

	score := extractScore(parsed.Content)
	return parsed.Content, score, nil
}

func (c *LlamaCppClient) GeneratePolicy(ctx context.Context, framework, description string) (string, error) {
	prompt := fmt.Sprintf(`You are a DevSecOps compliance officer. Generate a Fides validation policy rule in JSON format.
The policy should target compliance framework: "%s".
Description/Requirements: "%s".

Your output MUST be a valid JSON object matching the following structure:
{
  "name": "policy-name",
  "description": "Short description of what the policy verifies",
  "rules": {
    "controls": [
      {
        "name": "control-name",
        "attestation_type": "type-of-attestation (e.g. sbom, snyk-scan, unit-tests)",
        "jq_expressions": [
          "JQ rule expression returning boolean (e.g. .vulnerabilities[] | select(.severity == \\\"CRITICAL\\\") | length == 0)"
        ]
      }
    ]
  }
}
Output only the JSON block. Do not include any other markdown text.`, framework, description)

	reqBody, err := json.Marshal(llamaCppReq{
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/completion", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llama.cpp non-200: %d", resp.StatusCode)
	}

	var parsed llamaCppResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	return parsed.Content, nil
}

func (c *LlamaCppClient) Chat(ctx context.Context, history []ChatMessage, message string) (string, error) {
	var promptBuilder bytes.Buffer
	promptBuilder.WriteString("You are Fides, a multi-tenant compliance and supply chain audit assistant. You help manage flows, trails, and audit logs.\n")
	promptBuilder.WriteString("Here is the chat history:\n")
	for _, msg := range history {
		promptBuilder.WriteString(fmt.Sprintf("%s: %s\n", msg.Role, msg.Content))
	}
	promptBuilder.WriteString(fmt.Sprintf("User: %s\n", message))
	promptBuilder.WriteString("Response:")

	reqBody, err := json.Marshal(llamaCppReq{
		Prompt: promptBuilder.String(),
		Stream: false,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/completion", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llama.cpp non-200: %d", resp.StatusCode)
	}

	var parsed llamaCppResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	return parsed.Content, nil
}

// GeminiClient connects to Google's Gemini API
type GeminiClient struct {
	APIKey string
	Model  string
	Client *http.Client
}

func NewGeminiClient(apiKey, model string) *GeminiClient {
	if model == "" {
		model = "gemini-1.5-flash"
	}
	return &GeminiClient{
		APIKey: apiKey,
		Model:  model,
		Client: &http.Client{Timeout: 60 * time.Second},
	}
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiReq struct {
	Contents []geminiContent `json:"contents"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
}

type geminiResp struct {
	Candidates []geminiCandidate `json:"candidates"`
}

func (c *GeminiClient) EvaluateAttestation(ctx context.Context, attestationName, payloadType, payloadData string) (string, int, error) {
	prompt := fmt.Sprintf(`Analyze the following software build attestation evidence:
Attestation Name: %s
Payload Type: %s
Payload Data:
%s

You are a security and compliance auditor. Review the payload data above. Perform the following checks:
1. Identify any critical or high vulnerabilities, failing test cases, or licensing risks.
2. Confirm if the payload is compliant.
3. Output your assessment in markdown. Explain your reasoning.
4. Conclude with a compliance score between 0 (completely failed/unsafe) and 100 (fully compliant/safe) in this exact format:
COMPLIANCE_SCORE: <score>`, attestationName, payloadType, payloadData)

	reqBody, err := json.Marshal(geminiReq{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: prompt},
				},
			},
		},
	})
	if err != nil {
		return "", 0, err
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", c.Model, c.APIKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to call Gemini: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("gemini returned non-200 status: %d", resp.StatusCode)
	}

	var parsed geminiResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", 0, err
	}

	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", 0, fmt.Errorf("gemini returned an empty completion")
	}

	resultText := parsed.Candidates[0].Content.Parts[0].Text
	score := extractScore(resultText)
	return resultText, score, nil
}

func (c *GeminiClient) GeneratePolicy(ctx context.Context, framework, description string) (string, error) {
	prompt := fmt.Sprintf(`You are a DevSecOps compliance officer. Generate a Fides validation policy rule in JSON format.
The policy should target compliance framework: "%s".
Description/Requirements: "%s".

Your output MUST be a valid JSON object matching the following structure:
{
  "name": "policy-name",
  "description": "Short description of what the policy verifies",
  "rules": {
    "controls": [
      {
        "name": "control-name",
        "attestation_type": "type-of-attestation (e.g. sbom, snyk-scan, unit-tests)",
        "jq_expressions": [
          "JQ rule expression returning boolean (e.g. .vulnerabilities[] | select(.severity == \\\"CRITICAL\\\") | length == 0)"
        ]
      }
    ]
  }
}
Output only the JSON block. Do not include any other markdown text.`, framework, description)

	reqBody, err := json.Marshal(geminiReq{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: prompt},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", c.Model, c.APIKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini non-200: %d", resp.StatusCode)
	}

	var parsed geminiResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}

	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini returned empty response")
	}

	return parsed.Candidates[0].Content.Parts[0].Text, nil
}

func (c *GeminiClient) Chat(ctx context.Context, history []ChatMessage, message string) (string, error) {
	var geminiContents []geminiContent
	
	// Prepend system instructions
	geminiContents = append(geminiContents, geminiContent{
		Parts: []geminiPart{
			{Text: "You are Fides, a multi-tenant compliance and supply chain audit assistant. You help manage flows, trails, and audit logs. Use markdown in your responses."},
		},
	})

	for _, msg := range history {
		geminiContents = append(geminiContents, geminiContent{
			Parts: []geminiPart{
				{Text: fmt.Sprintf("%s: %s", msg.Role, msg.Content)},
			},
		})
	}

	geminiContents = append(geminiContents, geminiContent{
		Parts: []geminiPart{
			{Text: message},
		},
	})

	reqBody, err := json.Marshal(geminiReq{
		Contents: geminiContents,
	})
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", c.Model, c.APIKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini non-200: %d", resp.StatusCode)
	}

	var parsed geminiResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}

	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini returned empty response")
	}

	return parsed.Candidates[0].Content.Parts[0].Text, nil
}

// helper to parse "COMPLIANCE_SCORE: <score>" from the response
func extractScore(text string) int {
	var score int
	// Simple scan for the format in text
	_, err := fmt.Sscanf(text, "COMPLIANCE_SCORE: %d", &score)
	if err != nil {
		// Fallback parse search
		for i := 0; i < len(text)-18; i++ {
			if text[i:i+17] == "COMPLIANCE_SCORE:" {
				fmt.Sscanf(text[i:], "COMPLIANCE_SCORE: %d", &score)
				break
			}
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
