package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Feed the same JSON-RPC sequence the Fides client sends and assert the server
// answers initialize and tools/call (id 2) correctly, and ignores the
// initialized notification.
func TestServeHandshakeAndToolCall(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_pods"}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	serve(strings.NewReader(in), &out, `{"pods":[{"status":"Ready"}]}`)

	var responses []rpcResponse
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r rpcResponse
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("invalid response line %q: %v", line, err)
		}
		responses = append(responses, r)
	}

	// Exactly two responses: initialize (id 1) and tools/call (id 2). The
	// notification gets none.
	if len(responses) != 2 {
		t.Fatalf("expected 2 responses (init + call), got %d", len(responses))
	}
	if string(responses[0].ID) != "1" || string(responses[1].ID) != "2" {
		t.Fatalf("response ids = %s, %s", responses[0].ID, responses[1].ID)
	}

	// The tools/call result must carry the tool response in content[0].text.
	raw, _ := json.Marshal(responses[1].Result)
	var res struct {
		Content []struct {
			Type, Text string
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || len(res.Content) == 0 {
		t.Fatalf("tools/call result missing content: %s", raw)
	}
	if res.Content[0].Text != `{"pods":[{"status":"Ready"}]}` {
		t.Fatalf("tool response text = %q", res.Content[0].Text)
	}
}

func TestNotificationsGetNoResponse(t *testing.T) {
	var out bytes.Buffer
	serve(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"), &out, "x")
	if strings.TrimSpace(out.String()) != "" {
		t.Fatalf("notifications must not get a response, got %q", out.String())
	}
}
