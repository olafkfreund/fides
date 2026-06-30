{ pkgs, lib, config, ... }:

{
  # 1. Project Packages
  packages = with pkgs; [
    git
    jq
    sqlite
    prometheus # for local telemetry testing
    docker-compose
  ];

  # 2. Languages configurations
  languages.go = {
    enable = true;
    # Use the default (latest) Go; go.mod requires 1.26+, so do not pin an older release.
    package = pkgs.go;
  };

  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_20;
    npm.enable = true;
  };

  # 3. Environment Variables
  # NOTE: Never commit secrets here. Provide FIDES_ENCRYPTION_KEY (and DB_DSN)
  # via an untracked local file, e.g. add `dotenv.enable = true;` with a
  # git-ignored `.env`, or `export FIDES_ENCRYPTION_KEY=...` in your shell.
  # The encryption key should be 32 random bytes, base64-encoded:
  #   head -c 32 /dev/urandom | base64
  env = {
    FIDES_SERVER_URL = "http://localhost:8191";
    PORT = "8191";
  };

  # 4. Custom Helper Scripts
  scripts = {
    build-all.exec = ''
      echo "Building Fides Server, CLI, and MCP..."
      go build -o fides-server cmd/server/main.go
      go build -o fides cmd/cli/main.go
      go build -o fides-mcp cmd/mcp/main.go
      echo "Build complete."
    '';

    run-dev.exec = ''
      echo "Running Fides API Server in development mode..."
      go run cmd/server/main.go
    '';

    test-all.exec = ''
      echo "Running Go static analysis and tests..."
      go vet ./...
      go test -v ./...
    '';
  };

  # 5. Shell Welcome Hook
  enterShell = ''
    echo "============================================="
    echo "⚡ Welcome to Fides Compliance Development Shell ⚡"
    echo "============================================="
    echo "Available commands:"
    echo "  - build-all : Compile server, CLI, and MCP binaries"
    echo "  - run-dev   : Run server directly via go run"
    echo "  - test-all  : Run tests and vet linters"
    echo ""
    echo "Environment Variables set:"
    echo "  - FIDES_SERVER_URL: $FIDES_SERVER_URL"
    echo "============================================="
  '';
}
