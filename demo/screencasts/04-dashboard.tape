# Fides CLI — Live TUI dashboard + DORA metrics
# Render:  cd demo/screencasts && nix run nixpkgs#vhs -- 04-dashboard.tape
# Requires: FIDES_SERVER_URL, FIDES_API_TOKEN

Output out/04-dashboard.gif

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

Type "# DORA delivery metrics, straight from the evidence — no separate tool" Enter
Sleep 800ms
Type 'fides metrics' Enter
Sleep 3s

Type 'fides metrics deployment-frequency --weeks 12' Enter
Sleep 3s

Type "# Live terminal dashboard of server stats (checks, artifacts, coverage)" Enter
Sleep 800ms
Type 'fides dashboard' Enter
Sleep 4s
# quit the TUI
Type "q"
Sleep 1.5s
