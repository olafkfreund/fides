# Fides CLI — Adopt a framework, see coverage, enforce, export for auditors
# Render:  cd demo/screencasts && nix run nixpkgs#vhs -- 03-controls-coverage.tape
# Requires: FIDES_SERVER_URL, FIDES_API_TOKEN, ENV_ID

Output out/03-controls-coverage.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 720
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms

Hide
Type "PS1='$ '; clear" Enter
Show

Type "# Which frameworks can we adopt?" Enter
Sleep 800ms
Type 'fides control frameworks' Enter
Sleep 2.5s

Type "# Import a catalog (idempotent) — SOC2, ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX, SLSA, CRA" Enter
Sleep 800ms
Type 'fides control import --framework SOC2' Enter
Sleep 2.5s

Type "# See each control's evidence + environment coverage" Enter
Sleep 800ms
Type 'fides control coverage' Enter
Sleep 3s

Type "# Enforce a control (by key) on an environment — now releases are gated on it" Enter
Sleep 800ms
Type 'fides control enforce --key CC7.2 --env $ENV_ID' Enter
Sleep 2.5s

Type "# Continuous control-test timeline: evidence events + derived status over time" Enter
Sleep 800ms
Type 'fides control timeline --days 30' Enter
Sleep 3s

Type "# Auditor-ready export — per-framework, or NIST OSCAL JSON" Enter
Sleep 800ms
Type 'fides report --framework SOC2 --format oscal | head -20' Enter
Sleep 3s

Type "# The same view is live in the portal: Controls & Coverage" Enter
Sleep 3s
