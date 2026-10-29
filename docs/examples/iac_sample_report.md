# Q-SHIELD Cryptographic Scan Report

**Data:** Scan results
**Finished:** 2026-10-29T18:25:07.034728+00:00
**Repository:** docs/examples/iac_sample
**TLS host:** N/A
**TLS port:** N/A
**Scenario:** central
**Assumed CRQC horizon (years):** 15.0

## Full-scan summary

| Severity | Count |
| --- | ---: |
| critical | 0 |
| high | 1 |
| medium | 0 |
| low | 0 |
| info | 0 |

**Total assessments:** 1
**Displayed assessments:** 1 (track: all; minimum severity: info)
**Heuristic posture score:** N/A
Posture scores are planning aids, not compliance certification.

## Scan diagnostics

This report contains failed or partially analyzed stages. Unresolved settings are not automatically vulnerabilities.

- iac_scanner: main.tf: unknown_value — Missing, dynamic, templated or unrecognized setting; no vulnerability inferred.

## Static IaC coverage

**Coverage:** partial
**Files:** 1 analyzed / 1 attempted

Static declarations do not establish effective runtime TLS or PQC support.

| File / line | Setting | Result | Observed value |
| --- | --- | --- | --- |
| main.tf:4 | ssl_policy | issue | ELBSecurityPolicy-2016-08 |
| main.tf:9 | ssl_policy | unknown | &lt;unresolved&gt; |

## Assessment details

### [HIGH] Configured AWS TLS policy permits deprecated protocols

- **Rule:** IAC_AWS_LEGACY_TLS_POLICY
- **Asset:** main.tf
- **Algorithm:** Static IaC TLS configuration
- **Track:** conventional
- **Confidence:** medium
- **Priority:** 44.0
- **Rationale:** Configured AWS TLS policy permits deprecated protocols. Static configured intent only, not observed runtime TLS posture; applicability requires verification.
- **Action (immediate):** Select a documented policy requiring TLS 1.2 or later after checking client compatibility.
- **Reason:** Correct the explicitly observed configuration and verify the deployment.
- **Threat model:** Static security rule: Configured AWS TLS policy permits deprecated protocols.
