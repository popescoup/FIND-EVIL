"""
MABE Detector — Interactive Investigation Loop
===============================================
Version: 1.1.0

The primary UX artifact for the agentic workflow. Presents the incident
report and recommended actions in a clean terminal format, executes SIFT
tools on demand, passes output to an LLM summarizer, and maintains a
running investigation_notes.md for the case record.

TWO PUBLIC FUNCTIONS
--------------------
run_triage_queue()     — presents alerted account queue, analyst selects
                         which accounts to investigate, then runs
                         run_investigation_loop() for each selected account

run_investigation_loop() — interactive loop for one session: numbered
                           action prompts, tool execution, LLM summaries,
                           follow-on recommendations, notes

TERMINAL AESTHETIC
------------------
Uses ═══ separators for section headers, ─── for recommendation lists.
Numbered action prompts. [NEW] markers on dynamically-added follow-ons.

TOOL EXECUTION
--------------
MCP tools (command starts with "mcp:"): invoked directly as Python calls.
Shell commands: subprocess with timeout=120s, stdout+stderr captured.
Both paths feed output to a 3-5 sentence LLM summarizer before display.

HALLUCINATION GUARDRAILS
------------------------
Same rules as reporter_v2: [OBSERVED]/[INFERRED] tags on every LLM claim.
LLM receives tool output text, not the structured detection data.
On any LLM failure: print raw output, continue without summary.

INVESTIGATION NOTES
-------------------
investigation_notes.md is appended after each action. Never overwritten.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.recommendations import Recommendation
from sift.runner import SessionResult

logger = logging.getLogger(__name__)

# LLM summarizer system prompt
_SUMMARIZER_SYSTEM = """\
You are a forensic analyst summarizing tool output for an incident report.
Write 3-5 sentences. Every factual claim must be tagged [OBSERVED] (directly
in the output) or [INFERRED] (your interpretation). Plain English only —
no raw log lines, no hex values unless quoting a specific indicator.
Be direct and specific about what the tool found or did not find.\
"""

# Follow-on keyword triggers
_FOLLOWON_TRIGGERS = {
    "failed logon":  ("spray_analysis", "Analyze authentication failure patterns"),
    "4625":          ("spray_analysis", "Analyze authentication failure patterns"),
    "4768":          ("kerberos_deep",  "Kerberos deep-dive: extract all TGT/TGS requests"),
    "tgt":           ("kerberos_deep",  "Kerberos deep-dive: extract all TGT/TGS requests"),
    "as-rep":        ("kerberos_deep",  "Kerberos deep-dive: extract all TGT/TGS requests"),
}


# ---------------------------------------------------------------------------
# Public API — Triage queue
# ---------------------------------------------------------------------------

def run_triage_queue(
    alerted_accounts: list[dict],
    sift_output_dir: str,
    case_analysis_dir: str,
    case_reports_dir: str,
    anthropic_client=None,
) -> None:
    """
    Present the full alerted account queue and let the analyst select
    which accounts to investigate interactively.

    Parameters
    ----------
    alerted_accounts : list[dict]
        One entry per unique alerted account, sorted by max confidence
        descending. Each dict must have:
            account: str
            max_confidence: float
            alerted_sessions: int
            highest_session_id: str   -- UUID of highest-confidence session
            highest_layer: str        -- e.g. "all L3"
    sift_output_dir : str
        Absolute path to MABE output/sift/ directory.
    case_analysis_dir : str
        Absolute path to analysis output directory.
    case_reports_dir : str
        Absolute path to reports output directory.
    anthropic_client : anthropic.Anthropic | None
        Pre-instantiated client, or None to init from environment.
    """
    from sift.runner import DetectionRunner
    from sift.ingest import load_and_normalize, iter_normalized_sessions
    from sift.reporter_v2 import render_report_v2
    from core.recommendations import generate_recommendations

    client = anthropic_client or _init_client()

    # ── Print detection summary ───────────────────────────────────────
    print()
    print("=" * 60)
    print("  MABE DETECTOR — DETECTION COMPLETE")
    print(f"  {len(alerted_accounts)} accounts flagged across all alerted sessions")
    print("=" * 60)
    print()
    print("ALERTED ACCOUNTS (sorted by max confidence):")
    print("-" * 60)
    for i, acct in enumerate(alerted_accounts, 1):
        sessions_str = (
            f"{acct['alerted_sessions']} session"
            f"{'s' if acct['alerted_sessions'] != 1 else ''}"
        )
        print(
            f"[{i:2}] {acct['account']:<22}  "
            f"{acct['max_confidence']:.4f}  "
            f"{sessions_str:<12}  "
            f"{acct.get('highest_layer', '')}"
        )
    print("-" * 60)
    print()

    # ── Triage prompt ─────────────────────────────────────────────────
    while True:
        try:
            raw = input(
                f"Investigate accounts [1-{len(alerted_accounts)}], "
                f"enter numbers (e.g. 1,2,5), (a)ll, or (q)uit: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            return

        if raw.lower() == "q":
            print("  Exiting. Reports written to", case_reports_dir)
            return

        if raw.lower() == "a":
            selected = list(range(len(alerted_accounts)))
            break

        # Parse comma-separated numbers
        try:
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            selected = [int(p) - 1 for p in parts]
            if not selected:
                raise ValueError
            if any(i < 0 or i >= len(alerted_accounts) for i in selected):
                print(
                    f"  Invalid input. Enter numbers between 1 and "
                    f"{len(alerted_accounts)}."
                )
                continue
            break
        except ValueError:
            print(
                f"  Invalid input. Enter numbers (e.g. 1,2,5), (a)ll, or (q)uit."
            )
            continue

    # ── Load corpus once for baseline construction ────────────────────
    print()
    print("  Loading corpus for baseline construction...")
    all_sessions = list(iter_normalized_sessions(sift_output_dir, skip_empty=True))
    runner = DetectionRunner(alert_threshold=0.35)
    print(f"  {len(all_sessions)} sessions loaded.")
    print()

    # ── Investigate selected accounts ─────────────────────────────────
    for idx in selected:
        acct = alerted_accounts[idx]
        account = acct["account"]
        session_id = acct["highest_session_id"]
        session_path = f"{sift_output_dir}session_{session_id}"

        print("=" * 60)
        print(f"  INVESTIGATING: {account}")
        print(
            f"  Session: {session_id[:8]}...  "
            f"| Confidence: {acct['max_confidence']:.4f}"
        )
        print("=" * 60)
        print()

        # Load and detect
        try:
            session = load_and_normalize(session_path)
            result = runner.run_single(session, all_sessions)
        except Exception as exc:
            print(f"  Failed to load/detect session: {exc}")
            continue

        # Account context
        account_data = {
            "alerted_sessions": acct["alerted_sessions"],
            "confidence_range": {
                "min": acct["max_confidence"],
                "max": acct["max_confidence"],
            },
            "first_seen": result.correlation.triage_card.time_window.start,
            "last_seen":  result.correlation.triage_card.time_window.end,
        }

        # Generate recommendations
        recs = generate_recommendations(
            correlation_output=result.correlation,
            session_bundle_path=session_path,
            session_id=session_id,
            account=account,
            account_session_count=acct["alerted_sessions"],
            case_analysis_dir=case_analysis_dir,
        )

        # Write report
        report_path = Path(case_reports_dir) / f"report_{session_id[:8]}.md"
        try:
            render_report_v2(
                result, recs, account_data,
                report_path, anthropic_client=client
            )
            print(f"  Report: {report_path}")
        except Exception as exc:
            print(f"  Report generation failed: {exc}")

        # Run interactive investigation loop
        notes_path = Path(case_analysis_dir) / f"notes_{session_id[:8]}.md"
        run_investigation_loop(
            session_result=result,
            recommendations=recs,
            report_path=report_path,
            notes_path=notes_path,
            sift_output_dir=sift_output_dir,
            account_data=account_data,
            anthropic_client=client,
        )

        print()

    print("=" * 60)
    print("  INVESTIGATION COMPLETE")
    print(f"  Reports: {case_reports_dir}")
    print(f"  Notes:   {case_analysis_dir}")
    print("=" * 60)
    print()


# ---------------------------------------------------------------------------
# Public API — Per-session investigation loop
# ---------------------------------------------------------------------------

def run_investigation_loop(
    session_result: SessionResult,
    recommendations: list[Recommendation],
    report_path: Path,
    notes_path: Path,
    sift_output_dir: str,
    account_data: dict,
    anthropic_client=None,
) -> None:
    """
    Run the interactive investigation loop for one alerted session.

    Parameters
    ----------
    session_result : SessionResult
        Detection result for the session under investigation.
    recommendations : list[Recommendation]
        Ordered recommendations from generate_recommendations().
    report_path : Path
        Path to the incident report (for appending findings).
    notes_path : Path
        Path to investigation_notes.md (created/appended).
    sift_output_dir : str
        Absolute path to MABE output/sift/ directory (for MCP calls).
    account_data : dict
        Output of get_account_sessions() MCP call.
    anthropic_client : anthropic.Anthropic | None
        Pre-instantiated client, or None to init from environment.
    """
    c = session_result.correlation
    client = anthropic_client or _init_client()

    # Initialise notes file
    _init_notes(notes_path, c, report_path)

    # Working copy of recommendations — may grow with follow-ons
    active_recs: list[Recommendation] = list(recommendations)
    new_ids: set[int] = set()

    # Print header
    _print_header(c, account_data)

    while True:
        # Print recommendation list
        _print_recommendations(active_recs, new_ids)

        # Prompt
        try:
            raw = input(
                f"Run action [1-{len(active_recs)}], (s)kip, (q)uit: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Investigation complete.")
            _print_notes_path(notes_path)
            break

        if raw.lower() == "q":
            print("  Investigation complete.")
            _print_notes_path(notes_path)
            break

        if raw.lower() == "s":
            print("  Skipping remaining actions.")
            _print_notes_path(notes_path)
            break

        # Validate numeric input
        try:
            action_id = int(raw)
        except ValueError:
            print("  Invalid input. Enter a number, 's', or 'q'.")
            continue

        rec = next((r for r in active_recs if r.id == action_id), None)
        if rec is None:
            print(
                f"  Invalid input. Enter a number between 1 and "
                f"{len(active_recs)}, 's', or 'q'."
            )
            continue

        # Execute action
        print(f"\n  -> Running {rec.title}...")
        print()

        # Disk image / native EVTX check
        if rec.requires_disk_image or rec.status == "NEEDS NATIVE EVTX":
            msg = (
                f"  [NEEDS NATIVE EVTX] {rec.tool} requires native Windows "
                f"EVTX binary files. MABE bundles are JSON exports and cannot "
                f"be ingested by this tool. In a real-world deployment, run "
                f"this against the original Security.evtx from the host."
            )
            print(msg)
            _append_note(notes_path, rec, rec.command_template,
                         "Skipped — requires native EVTX files not available "
                         "in MABE JSON bundles.", [])
            print()
            continue

        # Execute
        output_text, actual_command = _execute_action(
            rec, sift_output_dir, c.session_id,
            c.triage_card.account, client
        )

        # Summarize
        summary = _summarize_output(output_text, rec.title, client)
        if summary:
            print(f"  {summary}")
        else:
            if output_text:
                preview = output_text[:500].strip()
                print(f"  Output preview:\n{preview}")
            else:
                print("  (No output produced.)")
        print()

        # Append to notes
        follow_ons = _detect_followons(output_text, active_recs)
        _append_note(
            notes_path, rec, actual_command,
            summary or output_text, follow_ons
        )

        # Add follow-on recommendations
        if follow_ons:
            max_id = max(r.id for r in active_recs)
            for fo in follow_ons:
                max_id += 1
                fo.id = max_id
                new_ids.add(max_id)
                active_recs.append(fo)
            print(
                f"  {len(follow_ons)} follow-on action(s) added [marked NEW]"
            )
            print()


# ---------------------------------------------------------------------------
# Action execution
# ---------------------------------------------------------------------------

def _execute_action(
    rec: Recommendation,
    sift_output_dir: str,
    session_id: str,
    account: str,
    client,
) -> tuple[str, str]:
    """
    Execute a recommendation. Returns (output_text, actual_command).

    MCP tools are invoked as Python calls.
    Shell commands are run via subprocess with timeout=120s.
    """
    if rec.command_template.startswith("mcp:"):
        return _execute_mcp_action(rec, sift_output_dir, account, client)
    else:
        return _execute_shell_action(rec)


def _execute_mcp_action(
    rec: Recommendation,
    sift_output_dir: str,
    account: str,
    client,
) -> tuple[str, str]:
    """Execute an MCP tool call directly as a Python function."""
    func_name = rec.command_template.split(":", 1)[1]
    actual_command = (
        f"mcp:{func_name}(account={account!r}, "
        f"sift_output_dir={sift_output_dir!r})"
    )

    try:
        if func_name == "get_account_sessions":
            from detector_mcp.server import get_account_sessions
            result = get_account_sessions(
                account=account,
                sift_output_dir=sift_output_dir,
            )
            output_text = json.dumps(result, indent=2)
        elif func_name == "run_batch_detection":
            from detector_mcp.server import run_batch_detection
            result = run_batch_detection(sift_output_dir=sift_output_dir)
            output_text = json.dumps(result, indent=2)
        else:
            output_text = f"Unknown MCP function: {func_name}"

        return output_text, actual_command

    except Exception as exc:
        error_text = f"MCP call failed: {exc}"
        logger.error("MCP action %s failed: %s", func_name, exc)
        return error_text, actual_command


def _execute_shell_action(rec: Recommendation) -> tuple[str, str]:
    """Execute a shell command with timeout=120s. Returns (output, command)."""
    command = rec.command_template

    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = proc.stdout
        if proc.returncode != 0 and proc.stderr:
            output += f"\nSTDERR:\n{proc.stderr}"
            print(f"  Command exited with code {proc.returncode}")
        return output, command

    except subprocess.TimeoutExpired:
        msg = f"Command timed out after 120s: {command}"
        logger.warning(msg)
        return msg, command
    except Exception as exc:
        msg = f"Command failed: {exc}"
        logger.error("Shell action failed: %s", exc)
        return msg, command


# ---------------------------------------------------------------------------
# LLM summarizer
# ---------------------------------------------------------------------------

def _summarize_output(
    output_text: str,
    action_title: str,
    client,
) -> Optional[str]:
    """
    Summarize tool output in 3-5 sentences with [OBSERVED]/[INFERRED] tags.
    Returns None on failure — caller prints raw output instead.
    """
    if not client or not output_text:
        return None

    truncated = output_text[:4000]

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=400,
            system=_SUMMARIZER_SYSTEM,
            messages=[{
                "role": "user",
                "content": (
                    f"Summarize the output of the following forensic tool "
                    f"action in 3-5 sentences.\n\n"
                    f"Action: {action_title}\n\n"
                    f"Output:\n{truncated}"
                ),
            }],
        )
        return response.content[0].text.strip()
    except Exception as exc:
        logger.warning("LLM summarizer failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Follow-on recommendation detection
# ---------------------------------------------------------------------------

def _detect_followons(
    output_text: str,
    existing_recs: list[Recommendation],
) -> list[Recommendation]:
    """
    Scan tool output for follow-on trigger keywords.
    Returns new Recommendation objects not already in existing_recs.
    """
    if not output_text:
        return []

    text_lower = output_text.lower()
    existing_keys = {(r.tool, r.skill) for r in existing_recs}
    new_recs: list[Recommendation] = []
    seen_types: set[str] = set()

    for keyword, (rec_type, title) in _FOLLOWON_TRIGGERS.items():
        if keyword.lower() not in text_lower:
            continue
        if rec_type in seen_types:
            continue
        seen_types.add(rec_type)

        if rec_type == "spray_analysis":
            rec = Recommendation(
                id=0,
                title=title,
                basis="Authentication failure pattern detected in tool output",
                tool="EvtxECmd",
                skill="windows-artifacts",
                command_template=(
                    "dotnet /opt/zimmermantools/net9/EvtxeCmd/EvtxECmd.dll "
                    "--vss --sd /opt/detector-sift/mabe/output/sift/ "
                    "--csv /cases/mabe-investigation/analysis/ "
                    "--csvf spray_analysis.csv"
                ),
                requires_disk_image=False,
                priority=2,
                status="READY",
            )
        elif rec_type == "kerberos_deep":
            rec = Recommendation(
                id=0,
                title=title,
                basis="Kerberos activity detected in tool output",
                tool="EvtxECmd",
                skill="windows-artifacts",
                command_template=(
                    "dotnet /opt/zimmermantools/net9/EvtxeCmd/EvtxECmd.dll "
                    "--vss --sd /opt/detector-sift/mabe/output/sift/ "
                    "--csv /cases/mabe-investigation/analysis/ "
                    "--csvf kerberos_deep.csv"
                ),
                requires_disk_image=False,
                priority=2,
                status="READY",
            )
        else:
            continue

        key = (rec.tool, rec.skill)
        if key not in existing_keys:
            new_recs.append(rec)
            existing_keys.add(key)

    return new_recs


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------

def _print_header(c, account_data: dict) -> None:
    from sift.reporter_v2 import _severity_label
    severity   = _severity_label(c.overall_confidence)
    start      = c.triage_card.time_window.start
    end        = c.triage_card.time_window.end
    account    = c.triage_card.account
    confidence = c.overall_confidence

    print()
    print("=" * 60)
    print(f"  INCIDENT REPORT -- {account}")
    print(f"  Severity: {severity}  |  Confidence: {confidence:.4f}")
    print(f"  Period: {start} -> {end}")
    print("=" * 60)
    print()
    print(c.triage_card.plain_english)
    print()


def _print_recommendations(
    recs: list[Recommendation],
    new_ids: set[int],
) -> None:
    print("RECOMMENDED ACTIONS:")
    print("-" * 60)
    for rec in recs:
        new_marker = "  [NEW]" if rec.id in new_ids else ""
        status_str = f"[{rec.status}]{new_marker}"
        print(f"[{rec.id}] {rec.title}  {status_str}")
        print(f"    {rec.basis}")
        print(f"    Tool: {rec.tool}")
        print()
    print("-" * 60)


def _print_notes_path(notes_path: Path) -> None:
    print(f"\n  Investigation notes: {notes_path}")


# ---------------------------------------------------------------------------
# Investigation notes
# ---------------------------------------------------------------------------

def _init_notes(
    notes_path: Path,
    c,
    report_path: Path,
) -> None:
    """Create investigation_notes.md if it does not exist."""
    notes_path = Path(notes_path)
    notes_path.parent.mkdir(parents=True, exist_ok=True)

    if notes_path.exists():
        return

    now = _now_iso()
    content = (
        f"# Investigation Notes -- {c.triage_card.account} "
        f"-- {c.session_id[:8]}\n\n"
        f"**Case opened:** {now}\n"
        f"**Session bundle:** {c.session_ref}\n"
        f"**Report:** {report_path}\n\n"
        f"---\n\n"
    )
    notes_path.write_text(content, encoding="utf-8")


def _append_note(
    notes_path: Path,
    rec: Recommendation,
    actual_command: str,
    findings: str,
    follow_ons: list[Recommendation],
) -> None:
    """Append one action's findings to investigation_notes.md."""
    now = _now_iso()
    fo_list = (
        "\n".join(f"- {fo.title}" for fo in follow_ons)
        if follow_ons else "None"
    )

    section = (
        f"## Action {rec.id} -- {rec.title}\n\n"
        f"**Executed:** {now}\n"
        f"**Tool:** {rec.tool}\n"
        f"**Basis:** {rec.basis}\n\n"
        f"**Command:**\n"
        f"```\n{actual_command}\n```\n\n"
        f"**Findings:**\n{findings}\n\n"
        f"**Follow-on recommendations generated:** {fo_list}\n\n"
        f"---\n\n"
    )

    with open(notes_path, "a", encoding="utf-8") as f:
        f.write(section)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _init_client():
    """Attempt to initialise Anthropic client from environment or .env file."""
    try:
        from dotenv import load_dotenv
        load_dotenv("/opt/detector-sift/.env", override=False)
        load_dotenv(str(Path(__file__).parent.parent / ".env"), override=False)
    except ImportError:
        pass

    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return None
        return anthropic.Anthropic(api_key=api_key)
    except ImportError:
        return None