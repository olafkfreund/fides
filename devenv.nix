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
    package = pkgs.go_1_22;
  };

  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_20;
    npm.enable = true;
  };

  # 3. Environment Variables
  env = {
    FIDES_SERVER_URL = "http://localhost:8191";
    FIDES_ENCRYPTION_KEY = "passphrase-secret-passphrase-secret";
    PORT = "8191";
  };

  # 4. Custom Helper Scripts
  scripts = {
    build-all.exec = ''
      echo "Building Fides Server and CLI..."
      go build -o fides-server cmd/server/main.go
      go build -o fides cmd/cli/main.go
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
    echo "  - build-all : Compile server and CLI binaries"
    echo "  - run-dev   : Run server directly via go run"
    echo "  - test-all  : Run tests and vet linters"
    echo ""
    echo "Environment Variables set:"
    echo "  - FIDES_SERVER_URL: $FIDES_SERVER_URL"
    echo "============================================="
  '';
}
