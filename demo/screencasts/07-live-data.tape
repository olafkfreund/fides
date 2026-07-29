# Fides CLI — live data tour (read-only; safe against a real server)
# Render:  cd demo/screencasts && FLOW_ID=... nix run nixpkgs#vhs -- 07-live-data.tape
# Requires: FIDES_SERVER_URL, FIDES_API_TOKEN, FLOW_ID. Read-only — no writes.

Output out/07-live-data.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 780
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 35ms

Hide
Type "PS1='$ '; clear" Enter
Show

Type "# Regulated frameworks Fides ships, and control coverage" Enter
Sleep 500ms
Type "fides control frameworks | jq 'map(.framework)'" Enter
Sleep 2.5s
Type "fides control coverage | jq '.controls[:6] | map({framework, control, coverage})'" Enter
Sleep 3s
Type "clear" Enter
Sleep 300ms

Type "# Continuous control-test timeline (evidence events per control)" Enter
Sleep 500ms
Type "fides control timeline --days 30 | jq '.controls[:4] | map({control, framework, events: (.events|length)})'" Enter
Sleep 3s
Type "clear" Enter
Sleep 300ms

Type "# Flows and their build trails" Enter
Sleep 500ms
Type "fides flow list | jq 'map({name, id})'" Enter
Sleep 2.5s
Type "fides flow trails --flow $FLOW_ID | jq '.[:6] | map(.name)'" Enter
Sleep 3s
Type "clear" Enter
Sleep 300ms

Type "# Search evidence: artifacts by name" Enter
Sleep 500ms
Type "fides search artifacts --name podtato | jq '.[:5] | map({name, sha256})'" Enter
Sleep 3s
Type "clear" Enter
Sleep 300ms

Type "# DORA delivery metrics, straight from the evidence" Enter
Sleep 500ms
Type "fides metrics | jq '{trails, attestations, deployments, compliance_rate, change_failure_rate}'" Enter
Sleep 3s
Type "fides metrics deployment-frequency --weeks 12 | jq '.[-3:]'" Enter
Sleep 3s
