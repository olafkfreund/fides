# setup-fides

Install the `fides` CLI in a GitHub Actions workflow and add it to `PATH` —
the equivalent of `actions/setup-node` for Fides. Downloads the release archive,
**verifies its SHA256**, and installs the binary.

## Usage

```yaml
- uses: olafkfreund/fides/.github/actions/setup-fides@main
  with:
    version: latest            # or a tag like v0.3.0
- run: fides --help
```

Pin a version and use it for provenance/gating:

```yaml
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: olafkfreund/fides/.github/actions/setup-fides@main
        with:
          version: v0.3.0
      - env:
          FIDES_SERVER_URL: https://fides.example.com
          FIDES_API_TOKEN: ${{ secrets.FIDES_API_TOKEN }}
        run: |
          fides artifact report --trail "$GITHUB_SHA" --sha256 "$DIGEST" ...
          fides change-gate --trail "$GITHUB_SHA"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `version` | `latest` | Release tag (e.g. `v0.3.0`) or `latest` |
| `repo` | `olafkfreund/fides` | owner/repo publishing the release archives |
| `token` | `${{ github.token }}` | token for the release API |

## Outputs

| Output | Description |
|--------|-------------|
| `version` | The resolved version installed |
| `path` | Install dir (already on `PATH`) |

Supports Linux and macOS runners (x64 / arm64). For the gate itself, see the
companion `fides-gate` action.
