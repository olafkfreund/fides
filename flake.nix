{
  description = "Fides — compliance, provenance & evidence-tracking system (server, CLI, MCP)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    devenv.url = "github:cachix/devenv";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, devenv, ... } @ inputs:
    let
      # Bump in lockstep with the git tag when cutting a release.
      version = "0.1.0";

      systems = [ "x86_64-linux" "i686-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
      pkgsFor = system: nixpkgs.legacyPackages.${system};

      # Single derivation building all four Go commands. buildGoModule installs
      # each subPackage under its directory name (server, cli, mcp, mcp-sensor);
      # postInstall renames them to the project's binary convention.
      fidesPackage = pkgs:
        pkgs.buildGoModule {
          pname = "fides";
          inherit version;

          # `self` copies only git-tracked files into the store, so the stray
          # `cli`/`server` binaries and untracked docs are excluded.
          src = self;

          # Pure Go (no cgo): builds stay hermetic and cross-compile cleanly.
          vendorHash = "sha256-7uYb4S6ndDpZW6XyX/xMkX8yRDjKMXY3HboXYy7YBbc=";

          subPackages = [
            "cmd/server"
            "cmd/cli"
            "cmd/mcp"
            "cmd/mcp-sensor"
          ];

          env.CGO_ENABLED = 0;
          ldflags = [ "-s" "-w" ];

          postInstall = ''
            mv "$out/bin/server"     "$out/bin/fides-server"
            mv "$out/bin/cli"        "$out/bin/fides"
            mv "$out/bin/mcp"        "$out/bin/fides-mcp"
            mv "$out/bin/mcp-sensor" "$out/bin/fides-mcp-sensor"
          '';

          # The RLS integration tests need a live Postgres; the full suite runs
          # in CI (go-build.yml), so keep the package build fast and hermetic.
          doCheck = false;

          meta = with pkgs.lib; {
            description = "Compliance, provenance & evidence-tracking system";
            homepage = "https://github.com/olafkfreund/fides";
            license = licenses.asl20;
            mainProgram = "fides";
            platforms = platforms.unix;
          };
        };
    in
    {
      packages = forAllSystems (system:
        let fides = fidesPackage (pkgsFor system); in {
          inherit fides;
          default = fides;
        });

      # `nix run .#server` / `.#mcp`; the default app is the CLI.
      apps = forAllSystems (system:
        let fides = fidesPackage (pkgsFor system); in {
          default = { type = "app"; program = "${fides}/bin/fides"; };
          server = { type = "app"; program = "${fides}/bin/fides-server"; };
          mcp = { type = "app"; program = "${fides}/bin/fides-mcp"; };
        });

      # Preserved verbatim: the project's devenv-based development shell.
      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [
              ./devenv.nix
            ];
          };
        });

      # Consumers add this overlay to get pkgs.fides.
      overlays.default = final: _prev: {
        fides = fidesPackage final;
      };

      # NixOS service module: services.fides (see nix/nixos-module.nix).
      nixosModules.default = import ./nix/nixos-module.nix self;

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
