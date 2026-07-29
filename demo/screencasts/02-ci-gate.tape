# Fides CLI — CI/CD gates and the exit-code convention (GitHub & GitLab)
# Render:  cd demo/screencasts && nix run nixpkgs#vhs -- 02-ci-gate.tape
# Requires: FIDES_SERVER_URL, FIDES_API_TOKEN, TRAIL_ID, DIGEST, ENV_ID
# Shows the 0 / 2 exit codes CI keys off: 0 = pass, 2 = blocked, 1 = broke.

Output out/02-ci-gate.gif

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

Type "# Gate commands return exit 2 when the verdict is FAIL — any CI job blocks on that." Enter
Sleep 1.2s

Type "# Policy gate: does this artifact's recorded evidence satisfy a named policy?" Enter
Sleep 800ms
Type 'fides assert --sha256 $DIGEST --policy no-critical-vulns; echo "exit=$?"' Enter
Sleep 2.5s

Type "# Signature gate: was the image signed (keyless) by OUR CI workflow?" Enter
Sleep 800ms
Type 'fides verify-image --sha256 $DIGEST --issuer https://token.actions.githubusercontent.com --signer https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main; echo "exit=$?"' Enter
Sleep 2.5s

Type "# Approval gate: four-eyes / segregation-of-duties met? (exit 2 = HOLD)" Enter
Sleep 800ms
Type 'fides change-gate --trail $TRAIL_ID; echo "exit=$?"' Enter
Sleep 2.5s

Type "# Runtime gate: does the live cluster satisfy the rule?" Enter
Sleep 800ms
Type `fides env verify --env $ENV_ID --server k8s-prod --tool get_pods --rule '.pods[].status == "Ready"'; echo "exit=$?"` Enter
Sleep 3s

Type "# In CI you wrap these with .github/actions/fides-gate or ci/gitlab/fides-gate.yml" Enter
Sleep 800ms
Type "# Same commands, same exit codes — see docs/ci-gate.md" Enter
Sleep 3s
