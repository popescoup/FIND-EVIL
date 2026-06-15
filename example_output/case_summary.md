# CASE SUMMARY — MABE-IR-2026-001

**AI-Driven Attack Investigation**
**Environment:** SANS SIFT Workstation (Ubuntu 22.04) | **Evidence mode:** strict read-only
**Detector:** MABE SIFT (`/opt/detector-sift/`) | **Threshold:** 0.35
**Generated:** 2026-06-15 (Phase 3, deterministic — no LLM) | **Timestamps:** UTC

---

## 1. Overview

| Metric | Value |
|--------|-------|
| Sessions evaluated | **1,425** |
| Sessions alerted (≥0.35) | **75** (5.3%) |
| Sessions skipped / failed | **0** |
| Accounts flagged | **15** |
| Confidence range (corpus) | 0.0000 – 0.5809 |
| Mechanisms | Enumeration (w 0.35), Privilege Escalation (w 0.40), Velocity (w 0.25) |

**Calibration confirmed the threshold.** The score distribution is cleanly
bimodal: benign mass sits at median 0.02 (p25=p75=p90=0.02), and the alert tail
begins at p95=0.3749. The threshold sweep holds **75 sessions from 0.25 through
0.35**, then drops to 68 at 0.40 — i.e. there is a clean gap with nothing in the
0.03–0.37 band. Threshold 0.35 sits inside that gap, so detection is insensitive
to small threshold changes. (Source: `analysis/calibration.json`.)

---

## 2. Compromised Accounts

One row per flagged account, sorted by max confidence (descending). Tiers:
**HIGH ≥0.55**, **MEDIUM 0.40–0.54**, **LOW 0.35–0.39**. Every account fired all
three mechanisms; "Layers" is the highest layer reached per mechanism on that
account's top session (Enum / PrivEsc / Velocity).
(Source: `analysis/alerted_accounts.json`.)

| # | Account | Max conf. | Alerted sessions | Layers (E/P/V) | Tier |
|---|---------|-----------|------------------|----------------|------|
| 1 | `joseph.davis` | 0.5809 | 1 | L3 / L3 / L3 | **HIGH** |
| 2 | `george.winfield` | 0.5791 | 2 | L3 / L3 / L3 | **HIGH** |
| 3 | `emily.webb` | 0.5721 | 1 | L3 / L3 / L3 | **HIGH** |
| 4 | `isabella.garcia` | 0.5678 | 1 | L3 / L3 / L3 | **HIGH** |
| 5 | `hannah.wheeler` | 0.5427 | 2 | L3 / L3 / L3 | MEDIUM |
| 6 | `grace.anderson` | 0.5280 | 6 | L3 / L3 / L3 | MEDIUM |
| 7 | `grace.wickham` | 0.5234 | 2 | L3 / L3 / L3 | MEDIUM |
| 8 | `richard.mason` | 0.5068 | 5 | L3 / L3 / L3 | MEDIUM |
| 9 | `nicholas.jackson` | 0.5063 | 7 | L3 / L3 / L3 | MEDIUM |
| 10 | `john.rivera` | 0.5045 | 7 | L3 / L3 / L3 | MEDIUM |
| 11 | `olivia.wimbleton` | 0.4923 | 5 | L3 / L3 / L3 | MEDIUM |
| 12 | `thomas.mercer` | 0.4904 | 7 | L3 / L3 / L3 | MEDIUM |
| 13 | `joseph.french` | 0.4903 | 7 | L3 / L3 / L3 | MEDIUM |
| 14 | `sarah.brady` | 0.4900 | 12 | L3 / L3 / L3 | MEDIUM |
| 15 | `edward.winger` | 0.4655 | 10 | L2 / L3 / L3 | MEDIUM |

**Tier totals:** 4 HIGH, 11 MEDIUM, 0 LOW. **75 alerted sessions** total across
the 15 accounts.

---

## 3. Key Findings

Derived from aggregated signal data across all 75 alerted sessions
(`analysis/all_sessions.json`, `analysis/detection_meta.json`) and the
deep-dive on the top session (`reports/report_58f40118.md`). No LLM.

1. **Uniform three-mechanism co-fire.** All **75/75** alerted sessions fired
   **all three** mechanisms simultaneously — Enumeration, Privilege Escalation,
   and Velocity (each: 75/75). Benign sessions show none of this; this is the
   signature of automated, multi-stage activity rather than isolated anomalies.

2. **Maximum-severity layering is the norm.** **63 of 75** alerted sessions
   reached **L3 (highest layer) on all three mechanisms**. Only the lowest-ranked
   account (`edward.winger`) tops out at L2 on Enumeration; every other account's
   peak session is all-L3.

3. **Machine-speed enumeration far outside baseline.** The top session
   (`joseph.davis` / `58f40118`) touched **180 distinct hosts** across **3 network
   segments** in **~4.5 minutes** (12:22:00 → 12:26:35 UTC) vs. a historical
   baseline of **6.89** destinations — a **26×** ratio. Aggregate auth rate was
   **1.93 events/sec vs. 0.0092 baseline (209×)**, with median inter-event gaps as
   low as 141 ms — timing inconsistent with human interaction.

4. **Domain-controller targeting with credential-access precursors.** Within the
   first ~2 seconds the top session authenticated to **both domain controllers**
   (DC-01, DC-02), interleaving successes with failures and **rejected Kerberos
   TGT requests** ~1.1 s before privileged auth (vs. 300 s baseline). This
   harvest-to-escalation pattern is the Privilege Escalation L3 trigger and is
   consistent with automated credential testing (matches a Kerberos AS-REP /
   TGT-abuse pattern).

5. **Detection is well-separated and reproducible.** The 0.03–0.37 score gap
   (Finding in §1) means the 75/1,425 alert set is robust to threshold choice.
   This run reproduced the established baseline exactly (1,425 / 75 / 15 / 0
   skipped / range 0.0–0.5809 / 63 all-L3).

---

## 4. Organizational Recommendations

Deterministic decision tree keyed on account tier (no LLM). All 15 accounts
fired all three mechanisms at L3 (14 of 15) — treat every flagged account as a
suspected credential compromise pending confirmation.

**Tier 1 — HIGH (conf ≥0.55): `joseph.davis`, `george.winfield`, `emily.webb`,
`isabella.garcia`**
- Immediately disable the account and force a credential reset; revoke active
  Kerberos tickets (KRBTGT-scoped where DC auth occurred).
- Isolate any host the account authenticated to that is classified high-value
  (domain controllers, DB/file servers).
- Open an IR ticket per account; preserve session bundles as evidence.

**Tier 2 — MEDIUM (conf 0.40–0.54): the remaining 11 accounts**
- Reset credentials and invalidate sessions within the standard IR SLA.
- Prioritize accounts with the **most alerted sessions** for review first —
  `sarah.brady` (12), `edward.winger` (10), `nicholas.jackson` / `john.rivera` /
  `thomas.mercer` / `joseph.french` (7 each) — repeated alerts indicate sustained
  or recurring automated activity, not a one-off.
- Hunt laterally for reuse of the same harvested credentials on other accounts.

**Tier 3 — LOW (conf 0.35–0.39): none in this case.**

**Organization-wide:**
- Enforce MFA on all interactive and DC-facing authentication; alert on Kerberos
  TGT failures clustered with rapid multi-host auth (the signature in §3).
- Add velocity/enumeration rate alerting (auth events/sec per account vs. its
  baseline) to the SIEM — the 209× velocity ratio would have fired in real time.
- Review domain-controller exposure: 4 of the top accounts reached DCs within
  seconds of session start.

---

## 5. Data-Source Caveat (honest limitation)

The MABE dataset is delivered as **JSON event bundles** (`security_events.json`,
`sysmon_events.json`, `session_manifest.json`), **not native EVTX / disk images**.
Consequently, two of the four Phase 2 recommended real-world actions could not
run against this evidence and are marked `[NEEDS NATIVE EVTX]` in the report:
**EvtxECmd** (expects native EVTX, not JSON) and **log2timeline** (rejects the
JSON source). The other two ran successfully against `58f40118`:

- **Action 1 — MCP Kerberos correlation** (`get_account_sessions`, joseph.davis):
  examined **18 sessions** over the ~16 h window of 2025-11-14/15; 1 session
  alerted (~0.58, all three mechanisms), a further **7 sessions fired only
  privilege-escalation at low confidence** below threshold, the rest clean.
- **Action 4 — YARA sweep** (`attack_framework.yar`): matched a single rule,
  **`KerberosASREPRoasting`**, on the session's security-events file — consistent
  with the credential-access precursors in §3.

**None of this affects the detection findings** — every signal in §3 traces to a
specific `event_id` in the JSON bundles (see the Evidence Chain in
`reports/report_58f40118.md`).

Phase 2 was run interactively for the **top-confidence account only**
(`joseph.davis` / `58f40118`). The other 14 accounts were detected in Phase 1 but
not individually triaged; their findings here derive from the structured
detection artifacts.

---

## 6. Artifacts & Investigation Notes

| Artifact | Path |
|----------|------|
| Detection metadata | `analysis/detection_meta.json` |
| Calibration (distribution, sweep, dataset stats) | `analysis/calibration.json` |
| Alerted-account queue (Phase 2 input) | `analysis/alerted_accounts.json` |
| Full per-session cache (1,425 records) | `analysis/all_sessions.json` |
| Phase 1 driver (single-run) | `analysis/phase1_detect.py` |
| Incident report — joseph.davis | `reports/report_58f40118.md` |
| Investigation notes — joseph.davis | `analysis/notes_58f40118.md` |

*Validation note: against the ground-truth labels in each `session_manifest.json`
(`is_attack` / `agent_type`), the detector previously scored Precision = Recall =
F1 = 1.0000 on this dataset (TP=75, FP=0, FN=0, TN=1,350). Manifests are used for
validation only — detection is performed blind to ground truth.*
