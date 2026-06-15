# Investigation Notes -- joseph.davis -- 58f40118

**Case opened:** 2026-06-14T11:09:15.699Z
**Session bundle:** /opt/detector-sift/mabe/output/sift/session_58f40118-6c1b-46f4-aa6e-6810c2ea5ec9
**Report:** /cases/mabe-investigation/reports/report_58f40118.md

---

## Action 1 -- Correlate Kerberos activity across all account sessions

**Executed:** 2026-06-15T23:41:31.083Z
**Tool:** MABE Detector MCP
**Basis:** Kerberos TGT request 1.1s before domain controller auth

**Command:**
```
mcp:get_account_sessions(account='joseph.davis', sift_output_dir='/opt/detector-sift/mabe/output/sift/')
```

**Findings:**
Across the roughly 16-hour observation window on November 14–15, 2025, the tool examined 18 Kerberos sessions associated with the account **joseph.davis** [OBSERVED]. One session triggered a formal alert at a moderate confidence score of approximately 0.58, with three detection mechanisms firing simultaneously — enumeration, privilege escalation, and high-velocity activity — all concentrated within a roughly four-and-a-half-minute window around midday on November 14 [OBSERVED]. An additional seven sessions fired only the privilege escalation mechanism at low confidence and did not cross the alert threshold, while the remaining sessions showed no suspicious indicators at all [OBSERVED]. The clustering of a high-velocity enumeration burst immediately followed by multiple lower-confidence privilege escalation signals across separate sessions [INFERRED] suggests a possible reconnaissance and lateral movement pattern using the compromised or misused account. The overall detection picture indicates that while only one session met the bar for a formal alert, the breadth of privilege escalation signals across the account's activity warrants deeper investigation [INFERRED].

**Follow-on recommendations generated:** None

---

## Action 4 -- YARA sweep for attack framework signatures

**Executed:** 2026-06-15T23:41:55.868Z
**Tool:** yara
**Basis:** Standard supplementary sweep for all alerted sessions

**Command:**
```
yara /opt/detector-sift/detector_mcp/yara_rules/attack_framework.yar /opt/detector-sift/mabe/output/sift/session_58f40118-6c1b-46f4-aa6e-6810c2ea5ec9/
```

**Findings:**
The YARA sweep identified a single rule match — **KerberosASREPRoasting** — triggered against the security events log file collected during this session [OBSERVED]. ASREPRoasting is a Kerberos attack technique that targets user accounts with pre-authentication disabled, allowing an attacker to request encrypted ticket data and attempt offline password cracking [INFERRED]. No additional attack framework signatures were matched across the scanned artifacts [OBSERVED]. The presence of this signature suggests the environment may have been subjected to credential harvesting activity targeting Active Directory accounts [INFERRED].

**Follow-on recommendations generated:** None

---

