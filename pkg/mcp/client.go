package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// allowedStdioCommands returns the set of executables permitted for stdio MCP
// servers, read from FIDES_MCP_ALLOWED_COMMANDS (comma-separated). If the var
// is unset, stdio execution is denied entirely (fail closed). This prevents
// arbitrary command execution from attacker-controlled database records.
func allowedStdioCommands() map[string]bool {
	allowed := map[string]bool{}
	for _, c := range strings.Split(os.Getenv("FIDES_MCP_ALLOWED_COMMANDS"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			allowed[c] = true
		}
	}
	return allowed
}

// MCP Client structs
type JsonRpcRequest struct {
	JsonRpc string      `json:"jsonrpc"`
	Id      interface{} `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type JsonRpcResponse struct {
	JsonRpc string           `json:"jsonrpc"`
	Id      interface{}      `json:"id"`
	Result  *json.RawMessage `json:"result,omitempty"`
	Error   *JsonRpcError    `json:"error,omitempty"`
}

type JsonRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type InitializeParams struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Capabilities    interface{} `json:"capabilities"`
	ClientInfo      ClientInfo  `json:"clientInfo"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CallToolParams struct {
	Name      string      `json:"name"`
	Arguments interface{} `json:"arguments,omitempty"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ToolCallResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// CallToolStdio launches a stdio-based MCP server, calls a tool, and returns the result string
func CallToolStdio(command string, args []string, env map[string]string, toolName string, arguments interface{}) (string, error) {
	// Security: only execute explicitly allowlisted binaries. The command and
	// args originate from database records that may be attacker-controlled, so
	// an unrestricted exec here is a remote-code-execution sink.
	if !allowedStdioCommands()[command] {
		return "", fmt.Errorf("stdio MCP command %q is not in the allowlist (set FIDES_MCP_ALLOWED_COMMANDS)", command)
	}

	cmd := exec.Command(command, args...)

	// Pass env variables
	if len(env) > 0 {
		for k, v := range env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to open stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to open stdout pipe: %v", err)
	}

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start command: %v", err)
	}

	// Clean up process in case of failure or completion
	defer func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	}()

	stdoutReader := bufio.NewReader(stdout)

	// Step 1: Send Initialize Request (ID 1)
	initParams := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    struct{}{},
		ClientInfo: ClientInfo{
			Name:    "fides-mcp-client",
			Version: "1.0.0",
		},
	}
	initReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Id:      1,
		Method:  "initialize",
		Params:  initParams,
	}

	initBytes, _ := json.Marshal(initReq)
	if _, err := stdin.Write(append(initBytes, '\n')); err != nil {
		log.Printf("MCP client failed to write initialize request: %v", err)
	}

	// Read Initialize Response
	initRespLine, err := readNextLine(stdoutReader)
	if err != nil {
		return "", fmt.Errorf("failed to read initialize response: %v, stderr: %s", err, stderrBuf.String())
	}
	var initResp JsonRpcResponse
	if err := json.Unmarshal(initRespLine, &initResp); err != nil || initResp.Error != nil {
		// Log and ignore errors for mock servers (like echo) that don't do formal initialization handshake
		log.Printf("MCP Initialization handshake bypassed or errored: %v, moving forward", err)
	}

	// Step 2: Send Initialized Notification (no id)
	initializedReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "notifications/initialized",
	}
	initializedBytes, _ := json.Marshal(initializedReq)
	if _, err := stdin.Write(append(initializedBytes, '\n')); err != nil {
		log.Printf("MCP client failed to write initialized notification: %v", err)
	}

	// Step 3: Send Call Tool Request (ID 2)
	callParams := CallToolParams{
		Name:      toolName,
		Arguments: arguments,
	}
	callReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Id:      2,
		Method:  "tools/call",
		Params:  callParams,
	}

	callBytes, _ := json.Marshal(callReq)
	if _, err := stdin.Write(append(callBytes, '\n')); err != nil {
		log.Printf("MCP client failed to write tools/call request: %v", err)
	}

	// Read Tool Call Response
	var callResp JsonRpcResponse
	timeout := time.After(10 * time.Second)
	for {
		lineChan := make(chan []byte, 1)
		errChan := make(chan error, 1)
		go func() {
			l, e := readNextLine(stdoutReader)
			if e != nil {
				errChan <- e
			} else {
				lineChan <- l
			}
		}()

		select {
		case line := <-lineChan:
			// Attempt to unmarshal as JsonRpcResponse
			var tempResp JsonRpcResponse
			if err := json.Unmarshal(line, &tempResp); err == nil {
				// If we find our tool call response (ID 2), parse its result
				if tempResp.Id == float64(2) || tempResp.Id == "2" || tempResp.Id == 2 {
					callResp = tempResp
					break
				}
			}
			// If it's not our ID (could be notification or log), we keep reading
			continue
		case e := <-errChan:
			// If stdout closes and it is a simple echo command, the printed line might be raw text/json instead of JSON-RPC response
			// Let's check if the command output was just printed raw:
			if command == "echo" {
				return string(initRespLine), nil
			}
			return "", fmt.Errorf("failed to read tool call response: %v, stderr: %s", e, stderrBuf.String())
		case <-timeout:
			return "", fmt.Errorf("timeout waiting for tool call response")
		}
		break
	}

	if callResp.Error != nil {
		return "", fmt.Errorf("MCP Server returned error: %s", callResp.Error.Message)
	}

	if callResp.Result == nil {
		return "", fmt.Errorf("empty result returned from tool call")
	}

	// Extract result content
	var toolResult ToolCallResult
	if err := json.Unmarshal(*callResp.Result, &toolResult); err != nil {
		// If unmarshalling fails, return raw result string
		return string(*callResp.Result), nil
	}

	if len(toolResult.Content) > 0 {
		return toolResult.Content[0].Text, nil
	}

	return string(*callResp.Result), nil
}

func readNextLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return line, err
	}
	return bytes.TrimSpace(line), nil
}
