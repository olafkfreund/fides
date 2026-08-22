# Fides CLI — gating on what a change INTRODUCED, offline.
#
# Render:  cd demo/screencasts && PATH="/path/to/fides-bin:$PATH" nix run nixpkgs#vhs -- 08-local-gates.tape
#
# Needs no server and no token: sbom diff and vuln diff read two files and
# print a diff. That is the point of the asset — this is the part of Fides a
# pipeline can adopt on day one, before anything has been recorded anywhere.
#
# The story: gating on a TOTAL vulnerability count means the gate is red from
# the day you turn it on and everyone learns to ignore it. Gating on the delta
# means red always means "this change did that".

Output out/08-local-gates.gif

Set Shell "bash"
Set FontSize 13
Set Width 1180
Set Height 820
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 35ms

Hide
Type "PS1='$ '; clear" Enter
Type "bash fixtures/seed-local-gates.sh && cd fixtures" Enter
# Two scans of the same service, a release apart. The second introduces one CVE.
Type "clear" Enter
Show

Type "# Two Trivy scans of the same service, one release apart." Enter
Sleep 2s
Type "fides vuln diff base.json current.json --format trivy" Enter
Sleep 5s

Type "" Enter
Type "# One CVE was introduced. Gate on that, not on the backlog:" Enter
Sleep 2s
Type 'fides vuln diff base.json current.json --format trivy --fail-on-new || echo "exit=$? (gate held the release)"' Enter
Sleep 5s

Type "" Enter
Type "# exit 2 is the whole CI integration - the job just fails." Enter
Sleep 3s

Type "clear" Enter
Type "# The same question for dependencies: what changed in the SBOM?" Enter
Sleep 2s
Type "fides sbom diff old-bom.json new-bom.json" Enter
Sleep 6s

Type "" Enter
Type "# Added, removed and version-changed - no server, no token, no trail." Enter
Sleep 4s
