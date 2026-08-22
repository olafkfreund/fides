#!/usr/bin/env bash
# Fixtures for 08-local-gates.tape.
#
# Kept in a script rather than inline in the tape because VHS's Type takes a
# quoted string and nested quotes break its parser -- and because a screencast
# whose inputs live in the repo can be re-recorded by anyone.
#
# Two Trivy scans of the same service one release apart, and the SBOMs to
# match: the newer scan introduces exactly one CVE, and the newer SBOM adds one
# component, drops one and bumps one.
set -euo pipefail
cd "$(dirname "$0")"

cat > base.json <<'JSON'
{"Results":[{"Target":"payments-api","Vulnerabilities":[
  {"VulnerabilityID":"CVE-2026-1111","Severity":"HIGH","PkgName":"openssl"}]}]}
JSON

cat > current.json <<'JSON'
{"Results":[{"Target":"payments-api","Vulnerabilities":[
  {"VulnerabilityID":"CVE-2026-1111","Severity":"HIGH","PkgName":"openssl"},
  {"VulnerabilityID":"CVE-2026-2222","Severity":"CRITICAL","PkgName":"libxml2"}]}]}
JSON

cat > old-bom.json <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
  {"name":"openssl","version":"3.0.1"},
  {"name":"zlib","version":"1.2.13"}]}
JSON

cat > new-bom.json <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
  {"name":"openssl","version":"3.0.2"},
  {"name":"libxml2","version":"2.12.0"}]}
JSON
