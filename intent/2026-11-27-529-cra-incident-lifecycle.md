---
status: draft
issue: 529
author: olafkfreund
---

# Intent: Track CRA incident deadlines and submission evidence

## Problem

The existing CRA report lists vulnerabilities in a time window. It gives operators no persistent awareness time, stage deadlines or history of what was submitted for an incident.

## Proposed outcome

Operators can track affected artifacts, awareness and submission history per case. Deadline calculations follow the applicable Article 14 trigger, overdue stages emit events, and authorized operators can export each stage and attest the actual submission on relevant trails.

## Affected users and systems

CRA reporting operators, vulnerability impact index, event sinks, and affected evidence trails.

## Constraints

Article 14 calculates the first two deadlines from awareness. The vulnerability final report runs from availability of a corrective or mitigating measure. The severe-incident final report runs from the incident notification. Validate export capabilities and submission workflow against ENISA before promising direct compatibility. [Article 14](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) [ENISA Single Reporting Platform](https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp)

## Open questions

Confirm whether the first release covers both case types, how operators record submissions, and which export formats the platform supports.
