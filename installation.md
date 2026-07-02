# Installing Fides

There are three ways to install the Fides binaries — pre-built **release
downloads**, **Nix / NixOS** (flake), or **building from source**. All three
give you the same four binaries: `fides-server`, `fides` (CLI), `fides-mcp`, and
`fides-mcp-sensor`.

The binaries need a PostgreSQL database and an evidence/object store to run the
full server — for a complete self-hosted stack see the
**[Getting Started guide](/getting_started.html)**, the
**[Integration & Setup Guide](/guide.html)**, or the Helm chart
(`charts/fides`, see [Setup & Seeding](docs/setup.md)).

---

## 1. Pre-built release binaries

Every tagged release publishes archives for Linux and macOS (amd64 + arm64),
each with a SHA-256 checksum, on the
**[Releases page](https://github.com/olafkfreund/fides/releases)**.

```sh
# Linux x86_64 — download, verify, and install the CLI
VER=v0.1.0
base="https://github.com/olafkfreund/fides/releases/download/${VER}"
curl -sSLO "${base}/fides_${VER}_linux_amd64.tar.gz"
curl -sSLO "${base}/fides_${VER}_linux_amd64.tar.gz.sha256"
sha256sum -c "fides_${VER}_linux_amd64.tar.gz.sha256"
tar -xzf "fides_${VER}_linux_amd64.tar.gz"
sudo install "fides_${VER}_linux_amd64/fides" /usr/local/bin/fides
fides --help
```

Swap `linux_amd64` for `linux_arm64`, `darwin_amd64`, or `darwin_arm64` for other
platforms. Each archive also contains `fides-server`, `fides-mcp`, and
`fides-mcp-sensor`.

---

## 2. Nix / NixOS (flake)

The repository is a Nix flake (requires Nix with `nix-command` and `flakes`
enabled).

```sh
# Run without installing anything
nix run github:olafkfreund/fides#server      # start the API server
nix run github:olafkfreund/fides -- --help   # the CLI (default app)

# Build the binaries into ./result/bin
nix build github:olafkfreund/fides#fides

# Install the CLI (and the other binaries) into your user profile
nix profile install github:olafkfreund/fides#fides
```

The flake exposes:

* **`packages.<system>.fides`** (also `default`) — all four binaries.
* **`apps`** — `default` (CLI), `server`, and `mcp`.
* **`overlays.default`** — adds `pkgs.fides` to nixpkgs.
* **`nixosModules.default`** — the `services.fides` module below.
* **`devShells.default`** — the project's `devenv` development shell (`nix develop`).

### NixOS service module

Add the flake as an input and enable `services.fides`:

```nix
{
  inputs.fides.url = "github:olafkfreund/fides";

  outputs = { self, nixpkgs, fides, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        fides.nixosModules.default
        {
          services.fides = {
            enable = true;
            port = 8080;
            openFirewall = true;

            # Secrets + connection string — kept out of the Nix store
            # (provision via agenix / sops-nix):
            environmentFile = "/run/secrets/fides.env";

            # Non-secret environment variables:
            settings = {
              STORAGE_DRIVER = "local";
              FIDES_PUBLIC_URL = "https://fides.example.com";
              FIDES_EVENTS_ENABLED = true;
            };
          };
        }
      ];
    };
  };
}
```

The `environmentFile` **must** provide at least `DB_DSN` — the server refuses to
start without it — plus `FIDES_ENCRYPTION_KEY` for evidence encryption:

```sh
# /run/secrets/fides.env  (mode 0400, provisioned by agenix / sops-nix)
DB_DSN=host=db.internal user=fides password=… dbname=fides sslmode=verify-full
FIDES_ENCRYPTION_KEY=…            # 32 random bytes, base64: head -c 32 /dev/urandom | base64
```

The unit runs hardened (systemd sandboxing; writable paths limited to its state
directory, `/var/lib/fides` by default) and applies its database migrations on
boot. See the [Integration & Setup Guide](/guide.html) for the full
`FIDES_*` / storage / AI environment reference.

---

## 3. Build from source

Requires **Go 1.26+**.

```sh
git clone https://github.com/olafkfreund/fides && cd fides
go build -o fides        ./cmd/cli
go build -o fides-server ./cmd/server
go build -o fides-mcp    ./cmd/mcp
```

---

## Next steps

* **[Getting Started](/getting_started.html)** — run the full stack locally with Docker Compose and walk the CLI.
* **[Integration & Setup Guide](/guide.html)** — production deployment, secret vaults, CI/CD templates.
* **[CLI reference](docs/cli-reference.md)** · **[MCP server](/mcp-server.html)**
