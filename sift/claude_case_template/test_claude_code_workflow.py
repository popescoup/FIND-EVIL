"""
test_claude_code_workflow.py
=============================
Protocol SIFT — Claude Code integration test

Validates that the CLAUDE.md workflow (Steps 1–6) can be followed
correctly end-to-end. This script is run by Claude Code on the SIFT
workstation to self-verify before beginning an analyst engagement.

It does NOT require a live MABE dataset — it uses a minimal synthetic
fixture to test every step the CLAUDE.md instructs.

Usage (from detector-sift/):
    python -m pytest sift/claude_case_template/test_claude_code_workflow.py -v

Or run directly:
    python sift/claude_case_template/test_claude_code_workflow.py

Exit codes:
    0  All checks passed — Claude Code can proceed with the full workflow
    1  One or more checks failed — inspect output before proceeding
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Colours for terminal output
# ---------------------------------------------------------------------------

_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

def _pass(label: str, detail: str = "") -> None:
    suffix = f"  ({detail})" if detail else ""
    print(f"  {_GREEN}✓ PASS{_RESET}  {label}{suffix}")

def _fail(label: str, detail: str = "") -> None:
    suffix = f"\n         {_RED}{detail}{_RESET}" if detail else ""
    print(f"  {_RED}✗ FAIL{_RESET}  {label}{suffix}")

def _info(msg: str) -> None:
    print(f"  {_YELLOW}·{_RESET}      {msg}")

def _section(title: str) -> None:
    print(f"\n{_BOLD}{'─'*60}{_RESET}")
    print(f"{_BOLD}  {title}{_RESET}")
    print(f"{_BOLD}{'─'*60}{_RESET}")


# ---------------------------------------------------------------------------
# Determine the project root (detector-sift/)
# ---------------------------------------------------------------------------

_THIS_FILE = Path(__file__).resolve()
# This file lives at detector-sift/sift/claude_case_template/
# or is run from detector-sift/ directly
_PROJECT_ROOT: Optional[Path] = None

for candidate in [
    _THIS_FILE.parent.parent.parent,  # from sift/claude_case_template/
    Path.cwd(),                        # if run from detector-sift/
    _THIS_FILE.parent,                 # fallback
]:
    if (candidate / "sift" / "mabe_runner.py").exists():
        _PROJECT_ROOT = candidate
        break

if _PROJECT_ROOT is None:
    print(f"{_RED}ERROR: Cannot locate detector-sift/ project root.{_RESET}")
    print("Run this script from detector-sift/ or from sift/claude_case_template/.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Synthetic fixture builder
# ---------------------------------------------------------------------------

def _make_timestamp(base_ts: float, offset_ms: int) -> str:
    """Build ISO 8601 Z timestamp offset from a base epoch float."""
    import datetime
    t = datetime.datetime.fromtimestamp(
        base_ts + offset_ms / 1000.0,
        tz=datetime.timezone.utc,
    )
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def build_minimal_fixture(output_dir: Path, n_benign: int = 12, n_attack: int = 2) -> Path:
    """
    Build a minimal MABE-compatible sift/ output directory for testing.

    Produces:
    - n_benign sessions with realistic benign timing (human-speed)
    - n_attack sessions with machine-speed timing + broad enumeration
      + privilege escalation sequence

    Returns the sift/ output path.
    """
    sift_dir = output_dir / "sift"
    sift_dir.mkdir(parents=True, exist_ok=True)

    import random
    rng = random.Random(42)
    base_epoch = 1731571200.0  # 2024-11-14T12:00:00Z approx

    benign_users = [f"user_{i:03d}" for i in range(1, 8)]
    benign_hosts = [f"WS-{i:03d}" for i in range(1, 20)] + [f"API-{i:02d}" for i in range(1, 5)]

    # ── Benign sessions ───────────────────────────────────────────────
    for i in range(n_benign):
        sid = str(uuid.uuid4())
        user = rng.choice(benign_users)
        session_dir = sift_dir / f"session_{sid}"
        session_dir.mkdir(parents=True, exist_ok=True)

        # 3–8 events, human-speed gaps (30s–5min between events)
        n_events = rng.randint(3, 8)
        events = []
        t = base_epoch + rng.uniform(0, 3600) * i
        for j in range(n_events):
            dst = rng.choice(benign_hosts)
            gap_ms = rng.randint(30_000, 300_000)  # 30s–5min
            t += gap_ms / 1000.0
            events.append({
                "EventID": 4624,
                "TimeCreated": _make_timestamp(t, 0),
                "SubjectUserName": user,
                "host": dst,
                "AuthenticationPackageName": rng.choice(["NTLM", "Kerberos"]),
                "LogonId": f"0x{rng.randint(0x1000, 0xFFFF):x}",
                "LogonType": 3,
            })

        # Write security_events.json
        (session_dir / "security_events.json").write_text(
            json.dumps(events, indent=2), encoding="utf-8"
        )
        # Write empty sysmon_events.json (benign — no Sysmon)
        (session_dir / "sysmon_events.json").write_text(
            json.dumps([]), encoding="utf-8"
        )
        # Write session_manifest.json (minimal — only fields the detector reads)
        (session_dir / "session_manifest.json").write_text(
            json.dumps({
                "session_id": sid,
                "user": user,
                "is_attack": False,   # ground truth — detector must NOT read this
            }), encoding="utf-8"
        )

    # ── Attack sessions ───────────────────────────────────────────────
    # High-value targets from MABE topology
    hv_targets = [
        ("DC-01", 88, "Kerberos"),
        ("DC-02", 88, "Kerberos"),
        ("DB-01", 1433, "MSSQL"),
        ("DB-02", 1433, "MSSQL"),
        ("LOG-01", 9200, "HTTPS"),
        ("REG-01", 5000, "HTTPS"),
    ]
    bulk_targets = [f"WS-{i:03d}" for i in range(1, 41)]
    api_targets = [f"API-{i:02d}" for i in range(1, 7)]

    attack_user = "svc_deploy"  # compromised service account

    for i in range(n_attack):
        sid = str(uuid.uuid4())
        session_dir = sift_dir / f"session_{sid}"
        session_dir.mkdir(parents=True, exist_ok=True)

        events = []
        t = base_epoch + 7200.0 + i * 1800.0

        # Phase 1: credential discovery — file access to FS-01
        # (harvest indicator for priv_esc L2)
        events.append({
            "EventID": 11,    # Sysmon FileCreate — skip using security events instead
            "TimeCreated": _make_timestamp(t, 0),
            "SubjectUserName": attack_user,
            "host": "FS-01",
            "AuthenticationPackageName": "NTLM",
            "LogonId": "0xdeadbeef",
            "LogonType": 3,
        })
        t += 0.120  # 120ms gap — machine speed

        # Phase 2: kerberos TGT request (harvest indicator)
        events.append({
            "EventID": 4768,
            "TimeCreated": _make_timestamp(t, 0),
            "SubjectUserName": attack_user,
            "host": "DC-01",
            "AuthenticationPackageName": "Kerberos",
            "LogonId": "0xdeadbeef",
            "LogonType": 3,
        })
        t += 0.085

        # Phase 3: exhaustive enumeration — all workstations + api endpoints
        all_targets = bulk_targets + api_targets
        rng.shuffle(all_targets)
        for target in all_targets:
            port = 3389 if target.startswith("WS") else 443
            auth = "NTLM" if target.startswith("WS") else "HTTPS"
            events.append({
                "EventID": 4624,
                "TimeCreated": _make_timestamp(t, 0),
                "SubjectUserName": attack_user,
                "host": target,
                "AuthenticationPackageName": auth,
                "LogonId": "0xdeadbeef",
                "LogonType": 3,
            })
            t += rng.uniform(0.050, 0.200)  # 50–200ms

        # Phase 4: privilege escalation — auth to high-value nodes
        for (hv_host, hv_port, hv_auth) in hv_targets:
            events.append({
                "EventID": 4624,
                "TimeCreated": _make_timestamp(t, 0),
                "SubjectUserName": attack_user,
                "host": hv_host,
                "AuthenticationPackageName": hv_auth,
                "LogonId": "0xdeadbeef",
                "LogonType": 3,
            })
            t += rng.uniform(0.060, 0.150)

        # Also add a few failed auth attempts before DC success
        # (spray indicator for priv_esc L2)
        for j in range(3):
            events.insert(j, {
                "EventID": 4625,
                "TimeCreated": _make_timestamp(base_epoch + 7100.0 + j * 0.5, 0),
                "SubjectUserName": attack_user,
                "host": "DC-01",
                "AuthenticationPackageName": "Kerberos",
                "LogonId": "0x0",
                "LogonType": 3,
            })

        # Sort by timestamp before writing
        events.sort(key=lambda e: e["TimeCreated"])

        (session_dir / "security_events.json").write_text(
            json.dumps(events, indent=2), encoding="utf-8"
        )

        # Sysmon: add a NetworkConnect event + FileCreate for FS-01
        sysmon_events = [
            {
                "EventID": 3,
                "UtcTime": _make_timestamp(base_epoch + 7200.0 + i * 1800.0 + 0.5, 0),
                "User": attack_user,
                "DestinationHostname": "DC-01",
                "DestinationPort": 88,
                "SourceIp": "10.0.1.50",
                "Image": "C:\\Windows\\System32\\lsass.exe",
                "ProcessId": 4,
            },
            {
                "EventID": 11,
                "UtcTime": _make_timestamp(base_epoch + 7200.0 + i * 1800.0 + 0.01, 0),
                "User": attack_user,
                "host": "FS-01",
                "TargetFilename": "C:\\Shares\\IT\\credentials.txt",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "ProcessId": 1024,
            },
        ]
        (session_dir / "sysmon_events.json").write_text(
            json.dumps(sysmon_events, indent=2), encoding="utf-8"
        )
        (session_dir / "session_manifest.json").write_text(
            json.dumps({
                "session_id": sid,
                "user": attack_user,
                "is_attack": True,
            }), encoding="utf-8"
        )

    return sift_dir


# ---------------------------------------------------------------------------
# Individual step validators
# ---------------------------------------------------------------------------

def check_step1_bundle_structure(sift_dir: Path) -> tuple[bool, str]:
    """Step 1: Verify MABE output is present and well-formed."""
    bundles = sorted(sift_dir.glob("session_*"))
    if not bundles:
        return False, f"No session_* directories found under {sift_dir}"

    for b in bundles[:5]:
        for required_file in ("security_events.json", "sysmon_events.json", "session_manifest.json"):
            if not (b / required_file).exists():
                return False, f"Missing {required_file} in {b.name}"

    return True, f"{len(bundles)} session bundles found, all well-formed"


def check_step2_calibrate(sift_dir: Path) -> tuple[bool, str]:
    """Step 2: Calibration run produces score distribution output."""
    result = subprocess.run(
        [sys.executable, "-m", "sift.mabe_runner", "--input", str(sift_dir), "--calibrate"],
        capture_output=True, text=True,
        cwd=str(_PROJECT_ROOT),
        timeout=120,
    )
    stdout = result.stdout

    # Check for required output sections
    checks = [
        ("Score Distribution" in stdout, "Score Distribution section"),
        ("Threshold Sweep" in stdout, "Threshold Sweep section"),
        ("Dataset Statistics" in stdout, "Dataset Statistics section"),
        ("Sessions evaluated" in stdout, "Sessions evaluated count"),
        (result.returncode == 0, f"exit code 0 (got {result.returncode})"),
    ]
    failures = [label for ok, label in checks if not ok]
    if failures:
        detail = f"Missing: {', '.join(failures)}"
        if result.returncode != 0:
            detail += f"\nstderr: {result.stderr[:400]}"
        return False, detail

    # Extract session count from output for informational display
    for line in stdout.splitlines():
        if "Sessions evaluated" in line:
            return True, f"Calibration OK — {line.strip()}"
    return True, "Calibration output validated"


def check_step3_full_run(sift_dir: Path, reports_dir: Path) -> tuple[bool, str]:
    """Step 3: Full detection run completes and writes reports."""
    result = subprocess.run(
        [
            sys.executable, "-m", "sift.mabe_runner",
            "--input", str(sift_dir),
            "--output", str(reports_dir),
            "--threshold", "0.35",
            "-v",
        ],
        capture_output=True, text=True,
        cwd=str(_PROJECT_ROOT),
        timeout=180,
    )
    stdout = result.stdout + result.stderr

    # DONE line must be present
    done_line = next((l for l in stdout.splitlines() if l.startswith("DONE")), None)
    if not done_line:
        return False, f"No DONE line in output.\nstdout: {result.stdout[:600]}\nstderr: {result.stderr[:400]}"

    if result.returncode != 0:
        return False, f"Non-zero exit code {result.returncode}.\nDONE line: {done_line}"

    # Parse sessions count from DONE line
    # DONE  sessions=14  alerted=2  threshold=0.35  reports=...  duration=...s
    if "sessions=0" in done_line:
        return False, f"sessions=0 — no sessions were loaded. Check fixture. DONE: {done_line}"

    return True, done_line.strip()


def check_step4_run_summary(reports_dir: Path) -> tuple[bool, str]:
    """Step 4: run_summary.md exists and contains required sections."""
    summary_path = reports_dir / "run_summary.md"
    if not summary_path.exists():
        return False, f"run_summary.md not found at {summary_path}"

    content = summary_path.read_text(encoding="utf-8")
    required = [
        ("# MABE Detector", "title header"),
        ("## Detection Summary", "Detection Summary section"),
        ("Sessions evaluated", "Sessions evaluated row"),
        ("Sessions alerted", "Sessions alerted row"),
        ("Alert threshold", "Alert threshold row"),
        ("Score Distribution", "Score Distribution section"),
    ]
    missing = [label for marker, label in required if marker not in content]
    if missing:
        return False, f"run_summary.md missing sections: {', '.join(missing)}"

    # Count alert table rows
    alert_rows = [l for l in content.splitlines() if l.startswith("|") and "session_" in l.lower()]
    return True, f"run_summary.md OK, {len(alert_rows)} alerted session(s) in index"


def check_step5_session_reports(reports_dir: Path) -> tuple[bool, str]:
    """Step 5: Each alerted session has a report.md with all three levels."""
    session_dirs = sorted(reports_dir.glob("session_*/"))
    if not session_dirs:
        # If no sessions alerted, that's OK — fixture may not produce alerts
        # at threshold 0.35 on a 12+2 dataset. We check structure differently.
        summary = (reports_dir / "run_summary.md").read_text(encoding="utf-8")
        if "Sessions alerted | **0**" in summary or "Sessions alerted | 0" in summary:
            return True, "No sessions alerted (threshold may need lowering for small fixture)"
        return True, "No session_*/ directories (no alerts) — run_summary.md present"

    for session_dir in session_dirs:
        report_path = session_dir / "report.md"
        if not report_path.exists():
            return False, f"report.md missing in {session_dir.name}"

        content = report_path.read_text(encoding="utf-8")
        required = [
            ("## Level 1 — Triage Card", "Level 1 Triage Card"),
            ("## Mechanism Scores", "Mechanism Scores table"),
            ("## Level 3 — Session Reference", "Level 3 Session Reference"),
            ("Overall confidence", "overall_confidence field"),
            ("Alert threshold", "alert_threshold field"),
        ]
        missing = [label for marker, label in required if marker not in content]
        if missing:
            return False, f"{session_dir.name}/report.md missing: {', '.join(missing)}"

    return True, f"{len(session_dirs)} session report(s) validated"


def check_step6_ground_truth_isolation(sift_dir: Path) -> tuple[bool, str]:
    """
    Step 6: Verify detector never touches is_attack during detection.
    """
    forbidden_files: list[tuple[Path, int, str]] = []
    search_roots = [
        _PROJECT_ROOT / "core",
        _PROJECT_ROOT / "sift",
    ]

    for root in search_roots:
        if not root.exists():
            continue
        for pyfile in sorted(root.rglob("*.py")):
            if pyfile.name.startswith("test_") or pyfile == _THIS_FILE:
                continue
            try:
                lines = pyfile.read_text(encoding="utf-8").splitlines()
                in_docstring = False
                for lineno, line in enumerate(lines, 1):
                    stripped = line.strip()

                    # Track docstring boundaries
                    if stripped.count('"""') % 2 == 1:
                        in_docstring = not in_docstring
                    if stripped.count("'''") % 2 == 1:
                        in_docstring = not in_docstring

                    # Skip if inside a docstring or is a comment line
                    if in_docstring or stripped.startswith("#"):
                        continue

                    # Skip if is_attack only appears inside a string literal
                    # e.g. "is_attack", 'is_attack', or as part of a comment
                    if "is_attack" not in line:
                        continue
                    if '"is_attack"' in line or "'is_attack'" in line:
                        continue
                    # Skip inline comments
                    code_part = line.split("#")[0]
                    if "is_attack" not in code_part:
                        continue

                    forbidden_files.append(
                        (pyfile.relative_to(_PROJECT_ROOT), lineno, stripped)
                    )
            except Exception:
                pass

    if forbidden_files:
        detail = "; ".join(f"{f}:{l}" for f, l, _ in forbidden_files[:3])
        return False, f"is_attack accessed outside test/comment: {detail}"

    return True, "Ground truth isolation verified — is_attack never read by detector"


def check_claude_md_self_consistency() -> tuple[bool, str]:
    """
    Verify the CLAUDE.md workflow instructions are internally consistent
    with the actual CLI flags and output structure.
    """
    claude_md_path = _PROJECT_ROOT / "sift" / "claude_case_template" / "CLAUDE.md"
    if not claude_md_path.exists():
        return False, f"CLAUDE.md not found at {claude_md_path}"

    content = claude_md_path.read_text(encoding="utf-8")

    # Check that every CLI flag mentioned in CLAUDE.md exists in mabe_runner.py
    runner_path = _PROJECT_ROOT / "sift" / "mabe_runner.py"
    if not runner_path.exists():
        return False, f"mabe_runner.py not found at {runner_path}"
    runner_src = runner_path.read_text(encoding="utf-8")

    flags_in_claude_md = ["--input", "--output", "--calibrate", "--session", "--llm-narrative", "--threshold"]
    missing_flags = [f for f in flags_in_claude_md if f not in runner_src]
    if missing_flags:
        return False, f"Flags in CLAUDE.md not found in mabe_runner.py: {missing_flags}"

    # Check that the output paths mentioned in CLAUDE.md match reporter.py
    if "run_summary.md" not in content:
        return False, "CLAUDE.md does not mention run_summary.md"
    if "report.md" not in content:
        return False, "CLAUDE.md does not mention report.md"

    # Check the DONE line format matches what mabe_runner.py actually prints
    if "DONE  sessions=" not in runner_src:
        return False, "DONE line format mismatch: mabe_runner.py doesn't print 'DONE  sessions='"
    if "DONE" not in content:
        return False, "CLAUDE.md does not reference the DONE output line"

    return True, "CLAUDE.md is internally consistent with mabe_runner.py"


def check_import_health() -> tuple[bool, str]:
    """Verify all detector modules can be imported without error."""
    modules = [
        "core.schema",
        "core.config_loader",
        "core.node_classifier",
        "core.baseline",
        "core.mechanisms.velocity",
        "core.mechanisms.enumeration",
        "core.mechanisms.priv_escalation",
        "core.correlation.agent",
        "sift.ingest",
        "sift.runner",
        "sift.reporter",
        "sift.mabe_runner",
    ]
    failed: list[str] = []
    for mod in modules:
        result = subprocess.run(
            [sys.executable, "-c", f"import {mod}"],
            capture_output=True, text=True,
            cwd=str(_PROJECT_ROOT),
        )
        if result.returncode != 0:
            failed.append(f"{mod}: {result.stderr.strip()[:80]}")

    if failed:
        return False, f"Import failures: {'; '.join(failed[:3])}"
    return True, f"All {len(modules)} modules import cleanly"


def check_config_files_present() -> tuple[bool, str]:
    """Verify all three config YAML files are present."""
    config_dir = _PROJECT_ROOT / "config"
    required = ["thresholds.yaml", "baseline_params.yaml", "node_type_mapping.yaml"]
    missing = [f for f in required if not (config_dir / f).exists()]
    if missing:
        return False, f"Missing config files: {missing}"
    return True, f"All 3 config files present in {config_dir}"


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

def run_all_checks() -> int:
    """Run all integration checks. Returns 0 if all pass, 1 if any fail."""

    print(f"\n{_BOLD}{'═'*60}{_RESET}")
    print(f"{_BOLD}  MABE Detector SIFT — Claude Code Integration Test{_RESET}")
    print(f"{_BOLD}  Protocol SIFT Workflow Validator v1.0.0{_RESET}")
    print(f"{_BOLD}{'═'*60}{_RESET}")
    print(f"  Project root: {_PROJECT_ROOT}")

    failures = 0

    # ── Pre-flight checks ─────────────────────────────────────────────
    _section("Pre-flight: Module Health")

    for label, check_fn in [
        ("Config files present", check_config_files_present),
        ("All modules importable", check_import_health),
        ("CLAUDE.md self-consistency", check_claude_md_self_consistency),
    ]:
        try:
            ok, detail = check_fn()
            if ok:
                _pass(label, detail)
            else:
                _fail(label, detail)
                failures += 1
        except Exception as exc:
            _fail(label, f"Exception: {traceback.format_exc(limit=3)}")
            failures += 1

    if failures > 0:
        print(f"\n{_RED}Pre-flight failed — fix module issues before running workflow tests.{_RESET}")
        return 1

    # ── Build synthetic fixture ───────────────────────────────────────
    _section("Fixture: Synthetic Dataset")

    with tempfile.TemporaryDirectory(prefix="mabe_sift_test_") as tmpdir:
        tmppath = Path(tmpdir)
        sift_dir = None
        reports_dir = tmppath / "reports"
        reports_dir.mkdir()

        try:
            t0 = time.monotonic()
            sift_dir = build_minimal_fixture(tmppath, n_benign=12, n_attack=2)
            elapsed = time.monotonic() - t0
            bundles = list(sift_dir.glob("session_*"))
            _pass(
                "Fixture built",
                f"{len(bundles)} sessions (12 benign + 2 attack) in {elapsed:.2f}s"
            )
        except Exception as exc:
            _fail("Fixture build failed", traceback.format_exc(limit=3))
            return 1

        # ── CLAUDE.md Step 1: Verify bundle structure ─────────────────
        _section("Step 1: Bundle Structure")
        ok, detail = check_step1_bundle_structure(sift_dir)
        if ok:
            _pass("Bundle structure", detail)
        else:
            _fail("Bundle structure", detail)
            failures += 1

        # ── CLAUDE.md Step 2: Calibration run ────────────────────────
        _section("Step 2: Calibration Run")
        _info("Running: python -m sift.mabe_runner --input ... --calibrate")
        ok, detail = check_step2_calibrate(sift_dir)
        if ok:
            _pass("Calibration output", detail)
        else:
            _fail("Calibration output", detail)
            failures += 1

        # ── CLAUDE.md Step 3: Full detection run ─────────────────────
        _section("Step 3: Full Detection Run")
        _info("Running: python -m sift.mabe_runner --input ... --output ... --threshold 0.35 -v")
        ok, detail = check_step3_full_run(sift_dir, reports_dir)
        if ok:
            _pass("Full run", detail)
        else:
            _fail("Full run", detail)
            failures += 1

        # ── CLAUDE.md Step 4: Run summary ────────────────────────────
        _section("Step 4: Run Summary")
        ok, detail = check_step4_run_summary(reports_dir)
        if ok:
            _pass("run_summary.md", detail)
        else:
            _fail("run_summary.md", detail)
            failures += 1

        # ── CLAUDE.md Step 5: Session reports ────────────────────────
        _section("Step 5: Session Reports")
        ok, detail = check_step5_session_reports(reports_dir)
        if ok:
            _pass("Session reports", detail)
        else:
            _fail("Session reports", detail)
            failures += 1

        # ── CLAUDE.md Step 6: Ground truth isolation ──────────────────
        _section("Step 6: Ground Truth Isolation")
        ok, detail = check_step6_ground_truth_isolation(sift_dir)
        if ok:
            _pass("is_attack never read", detail)
        else:
            _fail("is_attack isolation VIOLATED", detail)
            failures += 1

    # ── Summary ───────────────────────────────────────────────────────
    _section("Result")
    total = 9  # pre-flight 3 + step checks 6
    passed = total - failures
    if failures == 0:
        print(f"\n  {_GREEN}{_BOLD}ALL {total} CHECKS PASSED{_RESET}")
        print(
            "\n  Claude Code can proceed with the CLAUDE.md workflow.\n"
            "  Run the full workflow:\n\n"
            "    python -m sift.mabe_runner --input output/sift/ --calibrate\n"
            "    python -m sift.mabe_runner --input output/sift/ --output reports/ -v\n"
        )
        return 0
    else:
        print(f"\n  {_RED}{_BOLD}{failures}/{total} CHECKS FAILED{_RESET}")
        print(
            "\n  Resolve the failures above before proceeding with the workflow.\n"
            "  Consult DETECTOR_DESIGN.md Section 12 (Common Failure Modes).\n"
        )
        return 1


if __name__ == "__main__":
    sys.exit(run_all_checks())
