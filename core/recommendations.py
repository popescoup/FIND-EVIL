"""
MABE Detector — Recommendation Engine
=======================================
Version: 1.1.0

Fully deterministic. No LLM. Maps CorrelationOutput signal data to a
prioritized list of Recommendation objects. The recommendations drive both
the incident report (Part 1) and the interactive investigation loop.

Decision tree is implemented exactly as specified in the handoff.
Signal field names match Signal.name values from core/schema.py.

Priority levels:
    1 = immediate  — run before anything else
    2 = important  — run after priority 1 actions
    3 = supplementary — always-add baseline coverage

TOOL COMPATIBILITY NOTE
-----------------------
EvtxECmd, log2timeline, and YARA are designed for native Windows EVTX
binary files and on-disk artifacts. MABE produces JSON event exports
(security_events.json / sysmon_events.json) which these tools cannot
ingest directly.

In real-world deployments these tools work against native EVTX evidence.
In MABE deployments the MCP tools (get_account_sessions, run_batch_detection)
provide equivalent structured analysis of the JSON event data.

Recommendations that require native EVTX are marked:
    status="NEEDS NATIVE EVTX"
    requires_disk_image=True

This ensures the investigation loop displays them honestly rather than
failing silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.schema import (
    CorrelationOutput,
    EvidenceSummary,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)

# YARA rules ship with the detector — path relative to detector root
YARA_RULES_PATH = "/opt/detector-sift/detector_mcp/yara_rules/attack_framework.yar"


# ---------------------------------------------------------------------------
# Recommendation dataclass
# ---------------------------------------------------------------------------

@dataclass
class Recommendation:
    id: int
    title: str
    basis: str                # specific signal value: "Kerberos TGT 1.1s before DC auth"
    tool: str                 # display name: "EvtxECmd", "log2timeline", "yara", "MCP"
    skill: Optional[str]      # Protocol SIFT skill name, or None for MCP tools
    command_template: str     # shell command or "mcp:{function_name}"
    requires_disk_image: bool
    priority: int             # 1=immediate, 2=important, 3=supplementary
    status: str               # "READY", "NEEDS NATIVE EVTX", "NEEDS DISK IMAGE"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_recommendations(
    correlation_output: CorrelationOutput,
    session_bundle_path: str,
    session_id: str,
    account: str,
    account_session_count: int,
    case_analysis_dir: str,
) -> list[Recommendation]:
    """
    Generate ordered recommendations from signal data.

    Priority 1 first, then 2, then 3.
    Deduplicated by (tool, skill) pair — no duplicate tool invocations.

    Parameters
    ----------
    correlation_output : CorrelationOutput
        Full output from the correlation agent.
    session_bundle_path : str
        Absolute path to the session_* bundle directory.
    session_id : str
        UUID of the session under investigation.
    account : str
        Account identifier (e.g. "joseph.davis").
    account_session_count : int
        Total alerted sessions for this account across the corpus.
    case_analysis_dir : str
        Absolute path to the case analysis directory for tool output.

    Returns
    -------
    list[Recommendation]
        Ordered list, priority 1 first, deduped by (tool, skill).
    """
    sid8 = session_id[:8]
    bundle = session_bundle_path
    analysis = case_analysis_dir

    # Build evidence summary lookup: mechanism_id → EvidenceSummary
    evidence_by_mech: dict[str, EvidenceSummary] = {
        s.mechanism_id: s for s in correlation_output.evidence_summary
    }

    raw: list[Recommendation] = []
    seen: set[tuple[str, Optional[str]]] = set()  # (tool, skill) dedup key
    counter = [0]  # mutable counter for closure

    def _next_id() -> int:
        counter[0] += 1
        return counter[0]

    def _add(rec: Recommendation) -> None:
        key = (rec.tool, rec.skill)
        if key not in seen:
            seen.add(key)
            raw.append(rec)

    # ── Privilege escalation branch ───────────────────────────────────
    if MECHANISM_PRIV_ESC in correlation_output.mechanisms_fired:
        pe_summary = evidence_by_mech.get(MECHANISM_PRIV_ESC)
        if pe_summary:
            pe_signals = {s.name: s for s in pe_summary.top_signals}
            pe_events  = pe_summary.top_events

            # Kerberos TGT + fast escalation → MCP cross-session analysis
            # (EvtxECmd listed as reference for real-world EVTX deployments)
            has_kerberos = any(
                e.event_type == "kerberos_tgt_request" for e in pe_events
            )
            delta_signal = pe_signals.get("harvest_to_escalation_delta_s")
            if has_kerberos and delta_signal and delta_signal.observed < 60:
                delta = delta_signal.observed

                # MCP-based Kerberos analysis (works with MABE JSON)
                _add(Recommendation(
                    id=_next_id(),
                    title="Correlate Kerberos activity across all account sessions",
                    basis=f"Kerberos TGT request {delta:.1f}s before domain controller auth",
                    tool="MABE Detector MCP",
                    skill=None,
                    command_template="mcp:get_account_sessions",
                    requires_disk_image=False,
                    priority=1,
                    status="READY",
                ))

                # EvtxECmd reference recommendation (real-world EVTX only)
                _add(Recommendation(
                    id=_next_id(),
                    title="[Real-world] Extract Kerberos tickets via EvtxECmd",
                    basis=(
                        f"Kerberos TGT request {delta:.1f}s before DC auth — "
                        f"requires native EVTX files, not MABE JSON bundles"
                    ),
                    tool="EvtxECmd",
                    skill="windows-artifacts",
                    command_template=(
                        f"dotnet /opt/zimmermantools/net9/EvtxeCmd/EvtxECmd.dll "
                        f"-f <path_to_Security.evtx> "
                        f"--csv {analysis}/ --csvf kerberos_{sid8}.csv"
                    ),
                    requires_disk_image=True,
                    priority=2,
                    status="NEEDS NATIVE EVTX",
                ))

            # Deep credential chain → log2timeline (real-world only)
            depth_signal = pe_signals.get("chain_depth")
            if depth_signal and depth_signal.observed >= 2:
                depth = depth_signal.observed
                _add(Recommendation(
                    id=_next_id(),
                    title="[Real-world] Reconstruct privilege escalation timeline",
                    basis=(
                        f"Credential chain reached {depth:.0f} privilege level(s) — "
                        f"requires native EVTX files, not MABE JSON bundles"
                    ),
                    tool="log2timeline",
                    skill="plaso-timeline",
                    command_template=(
                        f"log2timeline.py {analysis}/{sid8}_priv.plaso "
                        f"<path_to_evtx_directory>/ && "
                        f"psort.py -o l2tcsv {analysis}/{sid8}_priv.plaso "
                        f"> {analysis}/timeline_priv_{sid8}.csv"
                    ),
                    requires_disk_image=True,
                    priority=2,
                    status="NEEDS NATIVE EVTX",
                ))

    # ── Enumeration branch ────────────────────────────────────────────
    if MECHANISM_ENUMERATION in correlation_output.mechanisms_fired:
        en_summary = evidence_by_mech.get(MECHANISM_ENUMERATION)
        if en_summary:
            en_signals = {s.name: s for s in en_summary.top_signals}

            # Many high-value contacts → full timeline (real-world only)
            hv_signal  = en_signals.get("high_value_node_contacts")
            seg_signal = en_signals.get("distinct_segment_count")
            if hv_signal and hv_signal.observed >= 3:
                count    = hv_signal.observed
                segments = int(seg_signal.observed) if seg_signal else "multiple"
                _add(Recommendation(
                    id=_next_id(),
                    title="[Real-world] Generate full session event timeline",
                    basis=(
                        f"{count:.0f} high-value node types contacted across "
                        f"{segments} network segments — "
                        f"requires native EVTX files, not MABE JSON bundles"
                    ),
                    tool="log2timeline",
                    skill="plaso-timeline",
                    command_template=(
                        f"log2timeline.py {analysis}/{sid8}_enum.plaso "
                        f"<path_to_evtx_directory>/ && "
                        f"psort.py -o l2tcsv {analysis}/{sid8}_enum.plaso "
                        f"> {analysis}/timeline_enum_{sid8}.csv"
                    ),
                    requires_disk_image=True,
                    priority=2,
                    status="NEEDS NATIVE EVTX",
                ))

            # Mostly-new hosts → cross-session MCP analysis
            nhr_signal = en_signals.get("new_host_ratio")
            if nhr_signal and nhr_signal.observed > 0.8:
                ratio = nhr_signal.observed
                _add(Recommendation(
                    id=_next_id(),
                    title=f"Analyze all alerted sessions for {account}",
                    basis=f"{ratio:.0%} of destinations never seen in account baseline",
                    tool="MABE Detector MCP",
                    skill=None,
                    command_template="mcp:get_account_sessions",
                    requires_disk_image=False,
                    priority=2,
                    status="READY",
                ))

    # ── Velocity branch ───────────────────────────────────────────────
    if MECHANISM_VELOCITY in correlation_output.mechanisms_fired:
        vel_summary = evidence_by_mech.get(MECHANISM_VELOCITY)
        if vel_summary:
            vel_signals = {s.name: s for s in vel_summary.top_signals}

            # Low CV (machine-consistent timing) → YARA sweep
            cv_signal = vel_signals.get("timing_cv")
            if cv_signal and cv_signal.observed < 0.3:
                cv = cv_signal.observed
                _add(Recommendation(
                    id=_next_id(),
                    title="Sweep for attack framework process artifacts",
                    basis=f"Timing consistency (CV {cv:.2f}) indicates machine execution",
                    tool="yara",
                    skill="yara-hunting",
                    command_template=f"yara {YARA_RULES_PATH} {bundle}/",
                    requires_disk_image=False,
                    priority=2,
                    status="READY",
                ))

    # ── Cross-session correlation (always add if multiple sessions) ───
    if account_session_count > 1:
        _add(Recommendation(
            id=_next_id(),
            title=f"Correlate all {account_session_count} alerted sessions for {account}",
            basis=f"Account has {account_session_count} alerted sessions",
            tool="MABE Detector MCP",
            skill=None,
            command_template="mcp:get_account_sessions",
            requires_disk_image=False,
            priority=1,
            status="READY",
        ))

    # ── Always-add supplementary YARA sweep ───────────────────────────
    _add(Recommendation(
        id=_next_id(),
        title="YARA sweep for attack framework signatures",
        basis="Standard supplementary sweep for all alerted sessions",
        tool="yara",
        skill="yara-hunting",
        command_template=f"yara {YARA_RULES_PATH} {bundle}/",
        requires_disk_image=False,
        priority=3,
        status="READY",
    ))

    # Sort by priority, then by insertion order (id)
    raw.sort(key=lambda r: (r.priority, r.id))

    # Re-number sequentially after sort
    for i, rec in enumerate(raw, 1):
        rec.id = i

    return raw