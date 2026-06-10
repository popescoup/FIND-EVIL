"""
Tests for sift/mabe_runner.py
==============================

Tests cover:
    - Argument parsing: required and optional flags
    - Exit codes: 0 success, 1 bad input, 2 bad config, 3 runtime error
    - _run_full: writes reports and returns 0
    - _run_calibrate: prints distribution, no reports written, returns 0
    - _run_single_session: finds bundle, evaluates, prints to stdout
    - Error paths: missing directory, empty corpus, bad threshold
    - --session partial UUID matching
    - Quiet mode: suppresses terminal output
    - Final summary line always printed (parseable by Claude Code)

All tests use temp directories and mock runner/reporter where needed
to stay fast and not depend on MABE being installed.

Run from detector-sift/:
    python -m pytest tests/test_mabe_runner.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch, call

_HERE = Path(__file__).parent
for candidate in [_HERE.parent / "sift", _HERE / "sift", _HERE]:
    if (candidate / "mabe_runner.py").exists():
        sys.path.insert(0, str(candidate.parent))
        break

from sift.mabe_runner import (
    main,
    _parse_args,
    _run_calibrate,
    _run_full,
    _run_single_session,
)
from sift.runner import DetectionResult, SessionResult, SIFT_ALERT_THRESHOLD
from core.schema import (
    CorrelationOutput, TriageCard, TimeWindow,
    MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
_T1 = "2025-11-14T09:00:00.000Z"
_T2 = "2025-11-14T09:05:00.000Z"


def _make_triage(account: str = "j.harrison", confidence: float = 0.72) -> TriageCard:
    return TriageCard(
        account=account,
        time_window=TimeWindow(start=_T1, end=_T2),
        overall_confidence=confidence,
        plain_english=f"Account {account} showed anomalous behavior.",
        mechanism_scores={
            MECHANISM_VELOCITY: 0.82,
            MECHANISM_ENUMERATION: 0.71,
            MECHANISM_PRIV_ESC: 0.0,
        },
    )


def _make_correlation(confidence: float = 0.72, alerted: bool = True) -> CorrelationOutput:
    return CorrelationOutput(
        session_id=_UUID,
        overall_confidence=confidence,
        alert_triggered=alerted,
        alert_threshold=0.35,
        weights_used={
            MECHANISM_VELOCITY: 0.25,
            MECHANISM_ENUMERATION: 0.35,
            MECHANISM_PRIV_ESC: 0.40,
        },
        mechanisms_fired=[MECHANISM_VELOCITY, MECHANISM_ENUMERATION] if alerted else [],
        mechanisms_absent=[MECHANISM_PRIV_ESC],
        highest_layer_per_mechanism={
            MECHANISM_VELOCITY: 2,
            MECHANISM_ENUMERATION: 3,
            MECHANISM_PRIV_ESC: 0,
        },
        high_confidence_floor_applied=False,
        triage_card=_make_triage(confidence=confidence),
        evidence_summary=[],
        session_ref=f"/cases/session_{_UUID}",
    )


def _make_session_result(confidence: float = 0.72) -> SessionResult:
    session = MagicMock()
    session.session_id = _UUID
    session.account = "j.harrison"
    session.bundle_dir = Path(f"/cases/session_{_UUID}")
    return SessionResult(
        session=session,
        correlation=_make_correlation(confidence),
        mechanism_outputs=[],
        evaluation_time_ms=10.0,
    )


def _make_detection_result(
    alerted: int = 1,
    total: int = 5,
) -> DetectionResult:
    results = []

    # Add alerted sessions
    for i in range(alerted):
        uuid = f"alert-{i:04d}-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        sr = _make_session_result(confidence=0.72)
        sr.correlation.session_id = uuid
        sr.correlation.triage_card.account = f"attacker{i}"
        results.append(sr)

    # Add benign sessions
    for i in range(total - alerted):
        uuid = f"benign{i:04d}-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        corr = _make_correlation(confidence=0.10, alerted=False)
        corr.session_id = uuid
        corr.triage_card.account = f"user{i}"
        s = MagicMock()
        s.session_id = uuid
        results.append(SessionResult(
            session=s,
            correlation=corr,
            mechanism_outputs=[],
            evaluation_time_ms=5.0,
        ))

    results.sort(key=lambda r: r.correlation.overall_confidence, reverse=True)

    return DetectionResult(
        sessions_evaluated=total,
        sessions_alerted=alerted,
        alert_threshold=0.35,
        results=results,
        dataset_stats={
            "velocity": {"mean_aggregate_rate": 0.11, "std_aggregate_rate": 0.04},
            "enumeration": {"mean_destination_count": 4.2, "std_destination_count": 1.8},
        },
        run_duration_s=2.5,
        run_timestamp=_T1,
    )


def _make_bundle_dir(output_dir: Path, uuid: str = _UUID) -> Path:
    """Create a minimal MABE session bundle in a temp directory."""
    bundle = output_dir / f"session_{uuid}"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "security_events.json").write_text("[]")
    (bundle / "sysmon_events.json").write_text("[]")
    (bundle / "session_manifest.json").write_text(json.dumps({
        "session_id": uuid,
        "is_attack": False,
        "agent_type": "benign_user",
        "user": "j.harrison",
        "session_start": _T1,
        "session_end": _T2,
        "hosts_touched": [],
        "total_events": 0,
        "ground_truth": {"enum_phases": [], "ttps": []},
    }))
    return bundle


# ---------------------------------------------------------------------------
# Test: argument parsing
# ---------------------------------------------------------------------------

class TestArgParsing(unittest.TestCase):

    def test_input_required(self):
        with self.assertRaises(SystemExit):
            _parse_args([])

    def test_input_parsed(self):
        args = _parse_args(["--input", "/some/path"])
        self.assertEqual(args.input, "/some/path")

    def test_output_default(self):
        args = _parse_args(["--input", "/some/path"])
        self.assertEqual(args.output, "reports")

    def test_output_custom(self):
        args = _parse_args(["--input", "/p", "--output", "/my/reports"])
        self.assertEqual(args.output, "/my/reports")

    def test_threshold_default(self):
        args = _parse_args(["--input", "/p"])
        self.assertAlmostEqual(args.threshold, SIFT_ALERT_THRESHOLD)

    def test_threshold_custom(self):
        args = _parse_args(["--input", "/p", "--threshold", "0.50"])
        self.assertAlmostEqual(args.threshold, 0.50)

    def test_llm_narrative_default_false(self):
        args = _parse_args(["--input", "/p"])
        self.assertFalse(args.llm_narrative)

    def test_llm_narrative_flag(self):
        args = _parse_args(["--input", "/p", "--llm-narrative"])
        self.assertTrue(args.llm_narrative)

    def test_calibrate_default_false(self):
        args = _parse_args(["--input", "/p"])
        self.assertFalse(args.calibrate)

    def test_calibrate_flag(self):
        args = _parse_args(["--input", "/p", "--calibrate"])
        self.assertTrue(args.calibrate)

    def test_session_default_none(self):
        args = _parse_args(["--input", "/p"])
        self.assertIsNone(args.session)

    def test_session_uuid(self):
        args = _parse_args(["--input", "/p", "--session", _UUID])
        self.assertEqual(args.session, _UUID)

    def test_verbose_flag(self):
        args = _parse_args(["--input", "/p", "-v"])
        self.assertTrue(args.verbose)

    def test_quiet_flag(self):
        args = _parse_args(["--input", "/p", "-q"])
        self.assertTrue(args.quiet)

    def test_no_summary_flag(self):
        args = _parse_args(["--input", "/p", "--no-summary"])
        self.assertTrue(args.no_summary)

    def test_short_flags(self):
        args = _parse_args(["-i", "/p", "-o", "/out", "-t", "0.40"])
        self.assertEqual(args.input, "/p")
        self.assertEqual(args.output, "/out")
        self.assertAlmostEqual(args.threshold, 0.40)


# ---------------------------------------------------------------------------
# Test: exit codes from main()
# ---------------------------------------------------------------------------

class TestExitCodes(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_input_dir_returns_1(self):
        code = main(["--input", str(self.tmp_path / "nonexistent")])
        self.assertEqual(code, 1)

    def test_bad_threshold_returns_2(self):
        code = main(["--input", str(self.tmp_path), "--threshold", "1.5"])
        self.assertEqual(code, 2)

    def test_bad_threshold_zero_returns_2(self):
        code = main(["--input", str(self.tmp_path), "--threshold", "0.0"])
        self.assertEqual(code, 2)

    def test_empty_input_dir_returns_1(self):
        code = main(["--input", str(self.tmp_path)])
        self.assertEqual(code, 1)

    @patch("sift.mabe_runner.DetectionRunner")
    @patch("sift.mabe_runner.ForensicReporter")
    def test_successful_run_returns_0(self, mock_reporter_cls, mock_runner_cls):
        # Wire mock runner to return a valid detection result
        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_detection_result(alerted=1, total=5)
        mock_runner_cls.return_value = mock_runner

        # Wire mock reporter to return a path list
        mock_reporter = MagicMock()
        mock_reporter.render.return_value = [
            self.tmp_path / "reports" / "run_summary.md"
        ]
        mock_reporter_cls.return_value = mock_reporter

        # Create a dummy input dir with at least one bundle so it passes
        # the directory-exists check
        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        with patch("sys.stdout", new_callable=StringIO):
            code = main([
                "--input", str(input_dir),
                "--output", str(self.tmp_path / "reports"),
                "-q",
            ])
        self.assertEqual(code, 0)

    @patch("sift.mabe_runner.DetectionRunner")
    def test_runner_exception_returns_3(self, mock_runner_cls):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = RuntimeError("unexpected failure")
        mock_runner_cls.return_value = mock_runner

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        code = main([
            "--input", str(input_dir),
            "--output", str(self.tmp_path / "reports"),
            "-q",
        ])
        self.assertEqual(code, 3)


# ---------------------------------------------------------------------------
# Test: calibration mode
# ---------------------------------------------------------------------------

class TestCalibrateMode(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @patch("sift.mabe_runner.DetectionRunner")
    def test_calibrate_returns_0(self, mock_runner_cls):
        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_detection_result(alerted=2, total=10)
        mock_runner_cls.return_value = mock_runner

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            code = main(["--input", str(input_dir), "--calibrate"])

        self.assertEqual(code, 0)

    @patch("sift.mabe_runner.DetectionRunner")
    def test_calibrate_prints_distribution(self, mock_runner_cls):
        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_detection_result(alerted=2, total=10)
        mock_runner_cls.return_value = mock_runner

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            main(["--input", str(input_dir), "--calibrate"])
            output = mock_out.getvalue()

        self.assertIn("Score Distribution", output)
        self.assertIn("Threshold Sweep", output)

    @patch("sift.mabe_runner.DetectionRunner")
    def test_calibrate_does_not_write_reports(self, mock_runner_cls):
        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_detection_result(alerted=1, total=5)
        mock_runner_cls.return_value = mock_runner

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)
        reports_dir = self.tmp_path / "reports"

        with patch("sys.stdout", new_callable=StringIO):
            main([
                "--input", str(input_dir),
                "--output", str(reports_dir),
                "--calibrate",
            ])

        # Calibrate mode must NOT create the reports directory
        self.assertFalse(reports_dir.exists())

    @patch("sift.mabe_runner.DetectionRunner")
    def test_calibrate_marks_current_threshold(self, mock_runner_cls):
        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_detection_result()
        mock_runner_cls.return_value = mock_runner

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            main(["--input", str(input_dir), "--calibrate", "--threshold", "0.35"])
            output = mock_out.getvalue()

        self.assertIn("current", output)


# ---------------------------------------------------------------------------
# Test: single session mode
# ---------------------------------------------------------------------------

class TestSingleSessionMode(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @patch("sift.mabe_runner.DetectionRunner")
    @patch("sift.mabe_runner.ForensicReporter")
    @patch("sift.mabe_runner.load_and_normalize")
    @patch("sift.mabe_runner.iter_normalized_sessions")
    def test_single_session_returns_0(
        self,
        mock_iter,
        mock_load,
        mock_reporter_cls,
        mock_runner_cls,
    ):
        # Set up mock normalized session
        mock_session = MagicMock()
        mock_session.session_id = _UUID
        mock_session.account = "j.harrison"
        mock_session.bundle_dir = self.tmp_path

        mock_load.return_value = mock_session
        mock_iter.return_value = iter([mock_session])

        # Set up mock runner
        mock_runner = MagicMock()
        mock_runner.run_single.return_value = _make_session_result()
        mock_runner_cls.return_value = mock_runner

        # Set up mock reporter
        mock_reporter = MagicMock()
        mock_reporter.render_single.return_value = "# Report\n\nContent here."
        mock_reporter_cls.return_value = mock_reporter

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir, uuid=_UUID)

        with patch("sys.stdout", new_callable=StringIO):
            code = main([
                "--input", str(input_dir),
                "--session", _UUID,
            ])

        self.assertEqual(code, 0)

    def test_missing_session_uuid_returns_1(self):
        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()

        code = main([
            "--input", str(input_dir),
            "--session", "nonexistent-uuid-0000-0000-000000000000",
        ])
        self.assertEqual(code, 1)

    def test_partial_uuid_match(self):
        """
        --session with a prefix should match the full UUID bundle directory.
        """
        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir, uuid=_UUID)

        # Patch out the actual evaluation to avoid needing a full corpus
        with patch("sift.mabe_runner.load_and_normalize") as mock_load, \
             patch("sift.mabe_runner.iter_normalized_sessions") as mock_iter, \
             patch("sift.mabe_runner.DetectionRunner") as mock_runner_cls, \
             patch("sift.mabe_runner.ForensicReporter") as mock_reporter_cls:

            mock_session = MagicMock()
            mock_session.session_id = _UUID
            mock_session.account = "user"
            mock_session.bundle_dir = input_dir / f"session_{_UUID}"
            mock_load.return_value = mock_session
            mock_iter.return_value = iter([mock_session])

            mock_runner = MagicMock()
            mock_runner.run_single.return_value = _make_session_result()
            mock_runner_cls.return_value = mock_runner

            mock_reporter = MagicMock()
            mock_reporter.render_single.return_value = "# Report"
            mock_reporter_cls.return_value = mock_reporter

            with patch("sys.stdout", new_callable=StringIO):
                code = main([
                    "--input", str(input_dir),
                    "--session", "aaaaaaaa",  # just a prefix
                ])

        self.assertEqual(code, 0)


# ---------------------------------------------------------------------------
# Test: output behavior
# ---------------------------------------------------------------------------

class TestOutputBehavior(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @patch("sift.mabe_runner.DetectionRunner")
    @patch("sift.mabe_runner.ForensicReporter")
    def test_final_summary_line_always_printed(
        self, mock_reporter_cls, mock_runner_cls
    ):
        """
        The DONE summary line must always be printed — it's what Claude
        Code and calling scripts parse to check success.
        """
        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_detection_result(alerted=1, total=5)
        mock_runner_cls.return_value = mock_runner

        mock_reporter = MagicMock()
        mock_reporter.render.return_value = []
        mock_reporter_cls.return_value = mock_reporter

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            # Even with --quiet, final line should print
            main(["--input", str(input_dir), "-q"])
            output = mock_out.getvalue()

        self.assertIn("DONE", output)
        self.assertIn("sessions=", output)
        self.assertIn("alerted=", output)

    @patch("sift.mabe_runner.DetectionRunner")
    @patch("sift.mabe_runner.ForensicReporter")
    def test_quiet_suppresses_run_summary(
        self, mock_reporter_cls, mock_runner_cls
    ):
        mock_runner = MagicMock()
        mock_runner.run.return_value = _make_detection_result()
        mock_runner_cls.return_value = mock_runner
        mock_reporter = MagicMock()
        mock_reporter.render.return_value = []
        mock_reporter_cls.return_value = mock_reporter

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            main(["--input", str(input_dir), "-q"])
            output = mock_out.getvalue()

        # Quiet mode should NOT contain the banner
        self.assertNotIn("RUN COMPLETE", output)

    @patch("sift.mabe_runner.DetectionRunner")
    @patch("sift.mabe_runner.ForensicReporter")
    def test_alerted_sessions_listed_in_output(
        self, mock_reporter_cls, mock_runner_cls
    ):
        mock_runner = MagicMock()
        dr = _make_detection_result(alerted=2, total=6)
        mock_runner.run.return_value = dr
        mock_runner_cls.return_value = mock_runner
        mock_reporter = MagicMock()
        mock_reporter.render.return_value = []
        mock_reporter_cls.return_value = mock_reporter

        input_dir = self.tmp_path / "sift"
        input_dir.mkdir()
        _make_bundle_dir(input_dir)

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            main(["--input", str(input_dir)])
            output = mock_out.getvalue()

        self.assertIn("Alerted sessions", output)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
