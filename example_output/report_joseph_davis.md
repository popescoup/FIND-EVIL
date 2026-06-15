# INCIDENT REPORT — joseph.davis

**Severity:** HIGH  |  **Confidence:** `0.5809`  |  **Session:** `58f40118-6c1b-46f4-aa6e-6810c2ea5ec9`
**Period:** 2025-11-14T12:22:00.438Z → 2025-11-14T12:26:35.016Z  |  **Generated:** 2026-06-15T23:27:34.311Z

---

## Executive Summary

On November 14, 2025, between 12:22 PM and 12:26 PM UTC, the account 'joseph.davis' exhibited behavior consistent with an automated, tool-assisted network reconnaissance and privilege escalation attempt. [OBSERVED] The account successfully authenticated to 180 distinct systems within roughly four and a half minutes — a volume far exceeding anything seen in this account's normal history. [OBSERVED] Within seconds of initial access, the account targeted both of the organization's domain controllers, which are among the most sensitive systems in the environment. [INFERRED] The speed and mechanical regularity of these actions strongly suggest the use of automated attack tooling rather than a person manually navigating the network. The overall confidence that this represents a genuine threat is moderate, meaning the activity is suspicious enough to warrant immediate investigation but cannot yet be confirmed as a full compromise. The potential severity is high: if the domain controller access attempts had succeeded fully, an attacker could have gained control over the entire organization's identity infrastructure.

---

## Incident Timeline

The incident began at 12:22 PM UTC on November 14, 2025. [OBSERVED] The account joseph.davis logged into an internal workstation — WS-026 — three times in rapid succession at the very same second, which is not consistent with normal human behavior. Within two seconds, the account shifted its attention to DC-01, one of the company's domain controllers, attempting to log in and request network authentication tickets multiple times. [OBSERVED] One of those login attempts to DC-01 succeeded; the authentication ticket requests did not. [OBSERVED] Roughly one second later, the account moved to a second domain controller, DC-02, again attempting to authenticate and request tickets, with the login succeeding but the ticket request failing. [INFERRED] The near-instant pivot from harvesting credentials on a workstation to targeting domain controllers — happening in just over one second — is a pattern associated with automated lateral movement tools rather than any manual user activity. At approximately 12:23 PM, [OBSERVED] the account successfully authenticated to two internal database servers, DB-03 and DB-04, in under two seconds. [OBSERVED] The activity concluded at 12:26 PM when the account successfully logged into a file server, FS-03. In total, across the four-and-a-half-minute window, the account touched systems across at least three separate network segments and made contact with four systems classified as high-value targets. [INFERRED] The pattern as a whole — machine-speed logins, breadth of systems reached, and immediate targeting of the most privileged systems in the environment — is consistent with a compromised account being leveraged by an attacker conducting reconnaissance and attempting to escalate their foothold within the network.

---

## Account Context

| | |
|---|---|
| **Account** | `joseph.davis` |
| **Alerted sessions** | 1 (confidence 0.5809 — 0.5809) |
| **First seen** | 2025-11-14T12:22:00.438Z |
| **Last seen** | 2025-11-14T12:26:35.016Z |
| **Detection mechanisms** | Enumeration, Privilege Escalation, Velocity |

---

## Attacker Accomplishments

- **Hosts contacted:** 180 distinct
- **High-value targets reached:** DC-01
- **Network segments accessed:** 3
- **Privilege escalation:** Yes — 1 level(s)
- **Credential harvest:** Probable — 1 credential(s) inferred

---

## Recommended Actions

[1] **Correlate Kerberos activity across all account sessions**  [READY]
     Kerberos TGT request 1.1s before domain controller auth
     Tool: MABE Detector MCP

[2] **[Real-world] Extract Kerberos tickets via EvtxECmd**  [NEEDS NATIVE EVTX]
     Kerberos TGT request 1.1s before DC auth — requires native EVTX files, not MABE JSON bundles
     Tool: EvtxECmd

[3] **[Real-world] Generate full session event timeline**  [NEEDS NATIVE EVTX]
     4 high-value node types contacted across 3 network segments — requires native EVTX files, not MABE JSON bundles
     Tool: log2timeline

[4] **YARA sweep for attack framework signatures**  [READY]
     Standard supplementary sweep for all alerted sessions
     Tool: yara

---

*(Technical appendix follows — mechanism scores, signal tables, evidence chain)*

---

# Technical Appendix — 58f40118

## Detection Mechanism Scores

| Mechanism | Weight | Confidence | Highest Layer | Status |
|-----------|--------|-----------|--------------|--------|
| Velocity | 0.25 | `0.6734` | L3 | fired (L3) |
| Enumeration | 0.35 | `0.8208` | L3 | fired (L3) |
| Privilege Escalation | 0.4 | `0.3133` | L3 | fired (L3) |

## Signal Details

### Velocity

| Signal | Observed | Baseline | Ratio | Contribution |
|--------|---------|---------|-------|-------------|
| `aggregate_rate_eps` | `1.9302` | `0.0092` | `209.2967x` | `1.00` |
| `median_inter_event_ms` | `817.5` | `239977.0` | `0.0034x` | `1.00` |
| `timing_cv` | `0.6609` | `1.2` | `0.5508x` | `1.00` |

### Enumeration

| Signal | Observed | Baseline | Ratio | Contribution |
|--------|---------|---------|-------|-------------|
| `distinct_destination_count` | `180.0` | `6.89` | `26.1085x` | `1.00` |
| `distinct_segment_count` | `3.0` | `1.0` | `3.0000x` | `0.50` |
| `high_value_node_contacts` | `4.0` | `0.0` | `4.0000x` | `0.50` |

### Privilege Escalation

| Signal | Observed | Baseline | Ratio | Contribution |
|--------|---------|---------|-------|-------------|
| `high_priv_node_types_contacted` | `1.0` | `0.0` | `1.0000x` | `1.00` |
| `harvest_to_escalation_delta_s` | `1.1` | `300.0` | `0.0037x` | `1.00` |
| `chain_depth` | `1.0` | `0.0` | `1.0000x` | `0.45` |

## Evidence Chain

Every finding above traces to one of these event references.

### Velocity

- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:23:01.815Z`** — auth_attempt @ 2025-11-14T12:23:01.815Z
  *fastest inter-event gap: 141ms to next event*
  user=`joseph.davis`, dst=`DB-03`, success=`True`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:23:02.009Z`** — auth_attempt @ 2025-11-14T12:23:02.009Z
  *event following 141ms gap*
  user=`joseph.davis`, dst=`DB-04`, success=`True`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:00.438Z`** — auth_attempt @ 2025-11-14T12:22:00.438Z
  *session start event*
  user=`joseph.davis`, dst=`WS-026`, success=`True`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:26:35.016Z`** — auth_attempt @ 2025-11-14T12:26:35.016Z
  *session end event*
  user=`joseph.davis`, dst=`FS-03`, success=`True`

### Enumeration

- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:02.662Z:0`** — auth_attempt @ 2025-11-14T12:22:02.662Z
  *access to high-value node type: domain_controller (DC-01)*
  user=`joseph.davis`, dst=`DC-01`, success=`True`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:02.662Z:1`** — auth_attempt @ 2025-11-14T12:22:02.662Z
  *access to high-value node type: domain_controller (DC-01)*
  user=`joseph.davis`, dst=`DC-01`, success=`False`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:02.662Z:2`** — kerberos_tgt_request @ 2025-11-14T12:22:02.662Z
  *access to high-value node type: domain_controller (DC-01)*
  user=`joseph.davis`, dst=`DC-01`, success=`False`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:00.438Z:3`** — auth_attempt @ 2025-11-14T12:22:00.438Z
  *successful auth to WS-026*
  user=`joseph.davis`, dst=`WS-026`, success=`True`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:00.438Z:4`** — auth_attempt @ 2025-11-14T12:22:00.438Z
  *successful auth to WS-026*
  user=`joseph.davis`, dst=`WS-026`, success=`True`

### Privilege Escalation

- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:02.662Z:0`** — auth_attempt @ 2025-11-14T12:22:02.662Z
  *successful auth to high-privilege node type: domain_controller (DC-01)*
  user=`joseph.davis`, dst=`DC-01`, success=`True`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:04.122Z:1`** — auth_attempt @ 2025-11-14T12:22:04.122Z
  *successful auth to high-privilege node type: domain_controller (DC-02)*
  user=`joseph.davis`, dst=`DC-02`, success=`True`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:02.662Z:2`** — kerberos_tgt_request @ 2025-11-14T12:22:02.662Z
  *credential access indicator preceding privilege escalation*
  user=`joseph.davis`, dst=`DC-01`, success=`False`
- **`58f40118-6c1b-46f4-aa6e-6810c2ea5ec9:2025-11-14T12:22:04.122Z:3`** — kerberos_tgt_request @ 2025-11-14T12:22:04.122Z
  *credential access indicator preceding privilege escalation*
  user=`joseph.davis`, dst=`DC-02`, success=`False`

## Raw Bundle Reference

```
/opt/detector-sift/mabe/output/sift/session_58f40118-6c1b-46f4-aa6e-6810c2ea5ec9
```

Files: `security_events.json`, `sysmon_events.json`, `session_manifest.json`

*Note: `session_manifest.json` contains ground truth labels — do not use for detection. Detection is performed blind to ground truth.*
