---
status: approved
issue: 554
author: olafkfreund
---

# Intent: Clear the reporter image scan

The reporter image scan flagged two dependency versions in the shipped Go
binary. The image should pass the existing scan with fixed dependencies.

The affected surface is the root Go module and the reporter image built from
it. Keep the existing build and scan gates.
