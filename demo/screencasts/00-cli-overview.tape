# Fides CLI — full feature reference (command surface + key subcommands)
# Render:  cd demo/screencasts && PATH="/path/to/fides-bin:$PATH" nix run nixpkgs#vhs -- 00-cli-overview.tape
# Needs NO server/token — prints usage only. Great "all features at a glance" asset.

Output out/00-cli-overview.gif

Set Shell "bash"
Set FontSize 13
Set Width 1180
Set Height 1000
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 35ms

Hide
Type "PS1='$ '; clear" Enter
Show

Type "fides --help" Enter
Sleep 5s
Type "clear" Enter
Sleep 300ms

Type "# Record a build + attach evidence (many parsers built in)" Enter
Sleep 500ms
Type "fides trail" Enter
Sleep 1.8s
Type "fides attest" Enter
Sleep 3s
Type "clear" Enter
Sleep 300ms

Type "# Governance controls + regulated frameworks" Enter
Sleep 500ms
Type "fides control" Enter
Sleep 3s
Type "clear" Enter
Sleep 300ms

Type "# EU AI Act model provenance (on the same tamper-evident chain)" Enter
Sleep 500ms
Type "fides model" Enter
Sleep 3.5s
Type "clear" Enter
Sleep 300ms

Type "# Runtime snapshots + ServiceNow (CMDB/ITSM/MCP/Now Assist grounding)" Enter
Sleep 500ms
Type "fides snapshot" Enter
Sleep 1.8s
Type "fides servicenow" Enter
Sleep 3.5s
