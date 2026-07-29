# Fides CLI — Advanced & newer features (AI-Act, authorship, flags, remediation, reports)
# Render:  cd demo/screencasts && nix run nixpkgs#vhs -- 06-advanced-new.tape
# Requires: FIDES_SERVER_URL, FIDES_API_TOKEN, TRAIL_ID, MODEL_FLOW, MODEL_TRAIL

Output out/06-advanced-new.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms

Hide
Type "PS1='$ '; clear" Enter
Show

Type "# Code authorship: is an AI-authored change human-reviewed? (gates the change)" Enter
Sleep 700ms
Type 'fides attest authorship --trail $TRAIL_ID --commit HEAD' Enter
Sleep 2.2s

Type "# Feature-flag flips are governed like deploys" Enter
Sleep 700ms
Type 'fides flag record --flag-key checkout-v2 --env production --from off --to on --source unleash' Enter
Sleep 2s
Type 'fides flag list --limit 5' Enter
Sleep 2.2s

Type "# --- EU AI Act model provenance (reuses trails + the tamper-evident chain) ---" Enter
Sleep 700ms
Type 'fides model register --flow $MODEL_FLOW --version 1.4.0 --risk-category high --purpose "credit scoring"' Enter
Sleep 2s
Type 'fides model attest --trail $MODEL_TRAIL --kind bias-audit --summary "no disparate impact" --compliant' Enter
Sleep 2s
Type 'fides model timeline --trail $MODEL_TRAIL' Enter
Sleep 2.5s

Type "# Policy-driven auto-remediation: propose -> approve -> apply" Enter
Sleep 700ms
Type 'fides remediation list' Enter
Sleep 2.2s

Type "# Auditor-ready reports: per-framework, NIST OSCAL, and the EU CRA 24h set" Enter
Sleep 700ms
Type 'fides report --framework SOC2 --format oscal | head -15' Enter
Sleep 2.5s
Type 'fides report --cra-incidents --hours 24' Enter
Sleep 2.5s

Type "# Correlate compliance verdicts with delivery outcomes" Enter
Sleep 700ms
Type 'fides metrics compliance-correlation --days 30' Enter
Sleep 2.5s

Type "# Ground ServiceNow Now Assist on Fides evidence for a change" Enter
Sleep 700ms
Type 'fides servicenow grounding --change CHG0030001' Enter
Sleep 3s
