# Fides CLI — Quickstart happy path (record → verify → gate)
# Render:  cd demo/screencasts && nix run nixpkgs#vhs -- 01-quickstart.tape
# Requires (exported before rendering — see README.md):
#   FIDES_SERVER_URL, FIDES_API_TOKEN, ORG_ID, FLOW_ID, ENV_ID
# The tape prints no secrets: env setup runs inside a Hide block.

Output out/01-quickstart.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 720
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms

Hide
Type "PS1='$ '; clear" Enter
Type "export TRAIL_ID=build-$(date +%s)" Enter
Show

Type "# 1. Open a build trail — this is the spine every piece of evidence hangs off" Enter
Sleep 800ms
Type 'fides trail start --flow $FLOW_ID --trail $TRAIL_ID --commit $(git rev-parse HEAD 2>/dev/null || echo demo) --committer "$USER@example.com"' Enter
Sleep 2.5s

Type "# 2. Register the artifact the build produced (SHA256 is its fingerprint)" Enter
Sleep 800ms
Type 'fides artifact report --org $ORG_ID --trail $TRAIL_ID --sha256 sha256:deadbeef... --name auth-service --type docker' Enter
Sleep 2.5s

Type "# 3. Attach evidence from a scanner you already run" Enter
Sleep 800ms
Type 'fides attest trivy --trail $TRAIL_ID --file trivy.json' Enter
Sleep 2.5s

Type "# 4. Prove the whole trail's evidence chain is untampered (exit 2 if broken)" Enter
Sleep 800ms
Type 'fides verify-chain --trail $TRAIL_ID' Enter
Sleep 2.5s

Type "# 5. Ask for a release verdict — evidence + risk score (exit 2 = HOLD)" Enter
Sleep 800ms
Type 'fides change-gate --trail $TRAIL_ID; echo "exit=$?"' Enter
Sleep 3s

Type "# That's the loop: record → verify → gate. Everything else builds on it." Enter
Sleep 3s
