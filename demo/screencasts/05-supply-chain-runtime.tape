# Fides CLI — Supply chain (SBOM/signatures/CVE) + runtime evidence
# Render:  cd demo/screencasts && nix run nixpkgs#vhs -- 05-supply-chain-runtime.tape
# Requires: FIDES_SERVER_URL, FIDES_API_TOKEN, TRAIL_ID, DIGEST, ENV_ID

Output out/05-supply-chain-runtime.gif

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

Type "# --- Supply chain provenance ---" Enter
Sleep 700ms
Type "# Ingest a CycloneDX/SPDX SBOM (a component is persisted per package)" Enter
Sleep 700ms
Type 'fides attest sbom --file sbom.cyclonedx.json --artifact-sha $DIGEST' Enter
Sleep 2.2s

Type "# Ingest SLSA in-toto provenance, and platform-native GitHub/GitLab attestations" Enter
Sleep 700ms
Type 'fides attest slsa --trail $TRAIL_ID --file provenance.intoto.jsonl' Enter
Sleep 2s
Type 'fides attest fetch --trail $TRAIL_ID --artifact-sha $DIGEST --provider github --repo org/repo' Enter
Sleep 2.2s

Type "# Which artifacts contain a component? Which are hit by a CVE?" Enter
Sleep 700ms
Type 'fides search components --name log4j' Enter
Sleep 2s
Type 'fides impact --cve CVE-2021-44228' Enter
Sleep 2.2s

Type "# Suppress a false positive with a VEX statement" Enter
Sleep 700ms
Type 'fides vex --cve CVE-2021-44228 --status not_affected --product $DIGEST --justification "not in classpath"' Enter
Sleep 2.2s

Type "# Anchor the trail's chain head to an external RFC3161 timestamp authority" Enter
Sleep 700ms
Type 'fides anchor --trail $TRAIL_ID' Enter
Sleep 2s
Type 'fides verify-chain --trail $TRAIL_ID' Enter
Sleep 2.5s

Type "# --- Runtime evidence ---" Enter
Sleep 700ms
Type "# Snapshot what is actually running (docker / k8s / ecs / lambda)" Enter
Sleep 700ms
Type 'fides snapshot k8s --env $ENV_ID --namespace production' Enter
Sleep 2.2s
Type "# Detect drift + shadow changes between snapshots" Enter
Sleep 700ms
Type 'fides env diff --env $ENV_ID' Enter
Sleep 2.5s

Type "# Per-environment artifact allow-list (check exits 2 if not approved)" Enter
Sleep 700ms
Type 'fides allowlist check --env $ENV_ID --sha $DIGEST; echo "exit=$?"' Enter
Sleep 3s
