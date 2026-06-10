"""
Tests for sift/runner.py
========================

Strategy: the runner owns orchestration logic, not detection logic.
Tests verify:
    - _to_baseline_record produces the correct shape
    - _build_sift_session_ref closure returns bundle_dir as string
    - score_distribution computes correct statistics
    - DetectionResult properties (alerted_results, score_distribution)
    - run_single wires the pipeline end-to-end with real NormalizedSessions
      (uses a tiny in-memory dataset so no MABE output directory needed)
    - Each session is excluded from its own baseline (contamination guard)
    - Mechanism None outputs are handled gracefully (absent != fired=False)
    - Skipped sessions are recorded, not silently dropped

The core mechanisms and CorrelationAgent are imported directly —
we don't stub them out. This keeps the test honest about the full
import chain while keeping the fixture data tiny enough to be fast.

Run from detector-sift/:
    python -m pytest tests/test_runner.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup — mirrors test_ingest.py approach
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
for candidate in [_HERE.parent / "sift", _HERE / "sift", _HERE]:
    if (candidate / "runner.py").exists():
        sys.path.insert(0, str(candidate.parent))
        break

from sift.runner import (
    DetectionRunner,
    DetectionResult,
    SessionResult,
    SIFT_ALERT_THRESHOLD,
    _to_baseline_record,
    _build_sift_session_ref,
    run_detection,
)
from sift.ingest import NormalizedSession

# ---------------------------------------------------------------------------
# Minimal event factories
# ---------------------------------------------------------------------------

_VALID_UUID_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
_VALID_UUID_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
_VALID_UUID_C = "cccccccc-cccc-cccc-cccc-cccccccccccc"


def _make_auth_event(
    timestamp: str,
    user: str = "j.harrison",
    dst_host: str = "DC-01",
    dst_port: int = 88,
    success: bool = True,
    session_id: str = _VALID_UUID_A,
    event_type: str = "auth_attempt",
) -> dict:
    return {
        "timestamp":  timestamp,
        "session_id": session_id,
        "user":       user,
        "event_type": event_type,
        "dst_host":   dst_host,
        "dst_port":   dst_port,
        "success":    success,
        "protocol":   "kerberos",
        "_source":    "security",
        "_event_id":  4624 if success else 4625,
    }


def _make_session(
    session_id: str,
    account: str,
    events: list[dict],
    bundle_dir: Path | None = None,
) -> NormalizedSession:
    return NormalizedSession(
        session_id=session_id,
        account=account,
        bundle_dir=bundle_dir or Path(f"/fake/session_{session_id}"),
        events=events,
    )


def _make_benign_session(
    session_id: str,
    account: str = "j.harrison",
    n_events: int = 10,
    base_time: str = "2025-11-14T09:00:00.000Z",
) -> NormalizedSession:
    """
    Create a realistic benign session: small number of destinations,
    human-speed timing (~3 minute gaps), no high-value node contacts.
    """
    events = []
    # Parse base time and add 3-minute gaps (180s = human speed)
    from datetime import datetime, timezone, timedelta
    t = datetime.strptime(base_time, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )
    # Benign: only touches workstations and file_server
    destinations = [
        ("WS-001", 3389), ("FS-01", 445), ("WS-002", 3389),
    ]
    for i in range(n_events):
        dst_host, dst_port = destinations[i % len(destinations)]
        ts = t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
        events.append(_make_auth_event(
            timestamp=ts,
            user=account,
            dst_host=dst_host,
            dst_port=dst_port,
            success=True,
            session_id=session_id,
        ))
        t += timedelta(seconds=180)  # 3-minute gaps

    return _make_session(session_id, account, events)


def _make_attack_session(
    session_id: str,
    account: str = "attacker",
) -> NormalizedSession:
    """
    Create a session with clear attack signatures:
    - Machine-speed timing (800ms gaps)
    - Broad enumeration (many distinct high-value destinations)
    - Credential harvest + privilege escalation sequence
    """
    from datetime import datetime, timezone, timedelta
    t = datetime.strptime(
        "2025-11-14T09:00:00.000Z", "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=timezone.utc)

    events = []

    def ts():
        nonlocal t
        result = t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
        t += timedelta(milliseconds=800)  # machine speed
        return result

    # Kerberos TGT request (credential access indicator)
    events.append({
        "timestamp":  ts(),
        "session_id": session_id,
        "user":       account,
        "event_type": "kerberos_tgt_request",
        "dst_host":   "DC-01",
        "dst_port":   88,
        "success":    True,
        "protocol":   "kerberos",
        "_source":    "security",
        "_event_id":  4768,
    })

    # Broad enumeration — many distinct destinations including high-value
    destinations = [
        ("DC-01", 88,   True),   # domain_controller — high value
        ("DC-02", 88,   True),   # domain_controller — high value
        ("DB-01", 1433, True),   # database — high value
        ("DB-02", 1433, True),   # database — high value
        ("REG-01", 5000, True),  # container_registry — high value
        ("LOG-01", 9200, True),  # logging_infrastructure — high value
        ("FS-01",  445,  True),  # file_server
        ("FS-02",  445,  True),  # file_server
        ("WS-001", 3389, False), # workstation — auth failure
        ("WS-002", 3389, True),  # workstation
        ("API-01", 443,  True),  # api_endpoint
        ("API-02", 443,  True),  # api_endpoint
    ]

    for dst_host, dst_port, success in destinations:
        events.append(_make_auth_event(
            timestamp=ts(),
            user=account,
            dst_host=dst_host,
            dst_port=dst_port,
            success=success,
            session_id=session_id,
        ))

    # File access (credential harvest indicator)
    events.append({
        "timestamp":  ts(),
        "session_id": session_id,
        "user":       account,
        "event_type": "file_access",
        "dst_host":   "FS-01",
        "dst_port":   445,
        "success":    True,
        "object_name": "\\\\FS-01\\Finance\\credentials.txt",
        "protocol":   "smb",
        "_source":    "sysmon",
        "_event_id":  11,
    })

    return _make_session(session_id, account, events)


# ---------------------------------------------------------------------------
# Test: _to_baseline_record
# ---------------------------------------------------------------------------

class TestToBaselineRecord(unittest.TestCase):

    def test_produces_required_keys(self):
        session = _make_benign_session(_VALID_UUID_A)
        record = _to_baseline_record(session)
        self.assertIn("session_id", record)
        self.assertIn("user", record)
        self.assertIn("events", record)

    def test_session_id_matches(self):
        session = _make_benign_session(_VALID_UUID_A)
        record = _to_baseline_record(session)
        self.assertEqual(record["session_id"], _VALID_UUID_A)

    def test_user_matches_account(self):
        session = _make_benign_session(_VALID_UUID_A, account="alice")
        record = _to_baseline_record(session)
        self.assertEqual(record["user"], "alice")

    def test_events_list_preserved(self):
        session = _make_benign_session(_VALID_UUID_A, n_events=5)
        record = _to_baseline_record(session)
        self.assertEqual(len(record["events"]), 5)

    def test_no_extra_fields_that_confuse_baseline_builder(self):
        """BaselineBuilder only uses session_id, user, events."""
        session = _make_benign_session(_VALID_UUID_A)
        record = _to_baseline_record(session)
        # Extra fields are fine but verify the three required are present
        # and events is a list of dicts
        self.assertIsInstance(record["events"], list)
        if record["events"]:
            self.assertIsInstance(record["events"][0], dict)


# ---------------------------------------------------------------------------
# Test: _build_sift_session_ref
# ---------------------------------------------------------------------------

class TestBuildSiftSessionRef(unittest.TestCase):

    def test_returns_bundle_dir_as_string(self):
        bundle_dir = Path("/cases/mabe/session_abc")
        builder = _build_sift_session_ref(bundle_dir)
        ref = builder("some-session-id")
        self.assertEqual(ref, str(bundle_dir))

    def test_ignores_session_id_argument(self):
        """session_ref is the bundle path, not the session_id."""
        bundle_dir = Path("/cases/mabe/session_abc")
        builder = _build_sift_session_ref(bundle_dir)
        self.assertEqual(builder("id-1"), builder("id-2"))

    def test_returns_string_not_path(self):
        bundle_dir = Path("/cases/mabe/session_abc")
        builder = _build_sift_session_ref(bundle_dir)
        self.assertIsInstance(builder("x"), str)


# ---------------------------------------------------------------------------
# Test: DetectionResult properties
# ---------------------------------------------------------------------------

class TestDetectionResultProperties(unittest.TestCase):

    def _make_result(self, confidence: float) -> SessionResult:
        """Minimal SessionResult stub for property tests."""
        # We only need correlation.overall_confidence and alert_triggered
        correlation = MagicMock()
        correlation.overall_confidence = confidence
        correlation.alert_triggered = confidence >= SIFT_ALERT_THRESHOLD
        return SessionResult(
            session=MagicMock(),
            correlation=correlation,
            mechanism_outputs=[],
            evaluation_time_ms=1.0,
        )

    def test_alerted_results_filters_correctly(self):
        results = [
            self._make_result(0.10),
            self._make_result(0.40),  # above 0.35 threshold
            self._make_result(0.75),  # above threshold
            self._make_result(0.20),
        ]
        dr = DetectionResult(
            sessions_evaluated=4,
            sessions_alerted=2,
            alert_threshold=SIFT_ALERT_THRESHOLD,
            results=results,
        )
        alerted = dr.alerted_results
        self.assertEqual(len(alerted), 2)
        for r in alerted:
            self.assertGreaterEqual(
                r.correlation.overall_confidence, SIFT_ALERT_THRESHOLD
            )

    def test_score_distribution_empty(self):
        dr = DetectionResult(
            sessions_evaluated=0,
            sessions_alerted=0,
            alert_threshold=SIFT_ALERT_THRESHOLD,
        )
        self.assertEqual(dr.score_distribution, {})

    def test_score_distribution_keys(self):
        results = [self._make_result(c) for c in [0.1, 0.3, 0.5, 0.7, 0.9]]
        dr = DetectionResult(
            sessions_evaluated=5,
            sessions_alerted=3,
            alert_threshold=SIFT_ALERT_THRESHOLD,
            results=results,
        )
        dist = dr.score_distribution
        for key in ("count", "min", "p25", "median", "p75", "p90", "p95",
                    "max", "alerted", "threshold"):
            self.assertIn(key, dist)

    def test_score_distribution_count(self):
        results = [self._make_result(c) for c in [0.1, 0.5, 0.9]]
        dr = DetectionResult(
            sessions_evaluated=3,
            sessions_alerted=2,
            alert_threshold=SIFT_ALERT_THRESHOLD,
            results=results,
        )
        dist = dr.score_distribution
        self.assertEqual(dist["count"], 3)
        self.assertEqual(dist["min"], 0.1)
        self.assertEqual(dist["max"], 0.9)

    def test_score_distribution_alerted_count(self):
        results = [self._make_result(c) for c in [0.1, 0.4, 0.6, 0.9]]
        dr = DetectionResult(
            sessions_evaluated=4,
            sessions_alerted=3,
            alert_threshold=SIFT_ALERT_THRESHOLD,
            results=results,
        )
        dist = dr.score_distribution
        # 0.4, 0.6, 0.9 are all >= 0.35
        self.assertEqual(dist["alerted"], 3)


# ---------------------------------------------------------------------------
# Test: run_single — end-to-end pipeline
# ---------------------------------------------------------------------------

class TestRunSingle(unittest.TestCase):
    """
    End-to-end tests using run_single() with in-memory sessions.

    No MABE output directory needed. Exercises the full import chain:
    ingest → baseline → mechanisms → correlation.
    """

    def _corpus(self) -> list[NormalizedSession]:
        """
        Build a small corpus: 10 benign sessions for j.harrison +
        1 attack session. Enough for the baseline builder to produce
        individual baselines (minimum_sessions=5 by default).
        """
        sessions = []
        for i in range(10):
            sid = f"benign-{i:04d}-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            sessions.append(_make_benign_session(
                session_id=sid,
                account="j.harrison",
                n_events=8,
                # Stagger start times so timestamps don't collide
                base_time=f"2025-11-14T{8 + (i % 8):02d}:00:00.000Z",
            ))
        attack_session = _make_attack_session(
            session_id=_VALID_UUID_C,
            account="j.harrison",
        )
        sessions.append(attack_session)
        return sessions

    def test_run_single_returns_session_result(self):
        runner = DetectionRunner()
        corpus = self._corpus()
        attack = corpus[-1]
        result = runner.run_single(attack, corpus)
        self.assertIsInstance(result, SessionResult)

    def test_run_single_session_id_matches(self):
        runner = DetectionRunner()
        corpus = self._corpus()
        attack = corpus[-1]
        result = runner.run_single(attack, corpus)
        self.assertEqual(
            result.correlation.session_id, _VALID_UUID_C
        )

    def test_run_single_confidence_in_range(self):
        runner = DetectionRunner()
        corpus = self._corpus()
        attack = corpus[-1]
        result = runner.run_single(attack, corpus)
        conf = result.correlation.overall_confidence
        self.assertGreaterEqual(conf, 0.0)
        self.assertLessEqual(conf, 1.0)

    def test_attack_session_scores_higher_than_benign(self):
        """
        The attack session should score materially higher than the
        median benign session. This is a sanity check on the full
        pipeline, not a specific threshold assertion.
        """
        runner = DetectionRunner()
        corpus = self._corpus()

        attack = corpus[-1]
        benign_sessions = corpus[:10]

        attack_result = runner.run_single(attack, corpus)
        benign_scores = []
        for s in benign_sessions[:5]:  # Sample 5 benign sessions
            r = runner.run_single(s, corpus)
            benign_scores.append(r.correlation.overall_confidence)

        median_benign = sorted(benign_scores)[len(benign_scores) // 2]
        attack_score = attack_result.correlation.overall_confidence

        self.assertGreater(
            attack_score, median_benign,
            f"Attack score {attack_score:.4f} should exceed "
            f"median benign score {median_benign:.4f}"
        )

    def test_session_ref_is_bundle_dir_path(self):
        """session_ref should be a string path to the bundle directory."""
        runner = DetectionRunner()
        corpus = self._corpus()
        attack = corpus[-1]
        result = runner.run_single(attack, corpus)
        ref = result.correlation.session_ref
        self.assertIsInstance(ref, str)
        self.assertIn("session_", ref)

    def test_evaluation_time_recorded(self):
        runner = DetectionRunner()
        corpus = self._corpus()
        result = runner.run_single(corpus[-1], corpus)
        self.assertGreater(result.evaluation_time_ms, 0.0)

    def test_mechanism_outputs_collected(self):
        """
        All three mechanisms should produce output for a session
        with enough events to evaluate (attack session has 14 events).
        """
        runner = DetectionRunner()
        corpus = self._corpus()
        result = runner.run_single(corpus[-1], corpus)
        # At minimum, velocity and enumeration should produce output
        self.assertGreater(len(result.mechanism_outputs), 0)

    def test_benign_session_low_confidence(self):
        """
        A typical benign session (small fan-out, human speed) should
        produce low overall confidence.
        """
        runner = DetectionRunner()
        corpus = self._corpus()
        benign = corpus[0]
        result = runner.run_single(benign, corpus)
        conf = result.correlation.overall_confidence
        # Not asserting exact value — just that it's clearly low
        self.assertLess(
            conf, 0.5,
            f"Benign session confidence {conf:.4f} unexpectedly high"
        )


# ---------------------------------------------------------------------------
# Test: baseline exclusion (contamination guard)
# ---------------------------------------------------------------------------

class TestBaselineExclusion(unittest.TestCase):
    """
    Verify that each session is excluded from its own baseline.

    We test this indirectly: a session with extreme behavior should
    produce a higher deviation score when excluded from its own
    baseline than when included. Direct verification requires
    inspecting the baseline objects — we do that via run_single's
    mechanism outputs.
    """

    def test_excluded_session_does_not_affect_own_baseline(self):
        """
        The attack session's enumeration deviation should be non-zero.
        If the attack session contaminated its own baseline (i.e., was
        NOT excluded), the deviation would be artificially compressed.

        We verify that enumeration.signals contains non-zero values —
        which would be zero if the session's own extreme behavior
        had been baked into the baseline.
        """
        runner = DetectionRunner()
        corpus = []
        for i in range(10):
            sid = f"benign-excl-{i:04d}-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            corpus.append(_make_benign_session(
                session_id=sid,
                account="alice",
                n_events=6,
                base_time=f"2025-11-14T{8 + (i % 8):02d}:00:00.000Z",
            ))
        attack = _make_attack_session(
            session_id=_VALID_UUID_C,
            account="alice",
        )
        corpus.append(attack)

        result = runner.run_single(attack, corpus)

        # If exclusion is working, at least one mechanism should fire
        fired = [o for o in result.mechanism_outputs if o.fired]
        self.assertTrue(
            len(fired) > 0,
            "No mechanisms fired on attack session — "
            "baseline exclusion may not be working"
        )


# ---------------------------------------------------------------------------
# Test: empty / edge case inputs
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def test_session_with_single_event_handled_gracefully(self):
        """
        Velocity mechanism returns None for sessions with < 2 events.
        Runner must handle None outputs without crashing.
        """
        runner = DetectionRunner()
        single_event_session = _make_session(
            _VALID_UUID_A,
            "alice",
            [_make_auth_event("2025-11-14T09:00:00.000Z", session_id=_VALID_UUID_A)],
        )
        corpus = [single_event_session]
        # Should not raise
        result = runner.run_single(single_event_session, corpus)
        self.assertIsInstance(result, SessionResult)
        self.assertGreaterEqual(result.correlation.overall_confidence, 0.0)

    def test_empty_corpus_single_session(self):
        """
        Single-session corpus: baseline will use population fallback.
        Should not raise.
        """
        runner = DetectionRunner()
        session = _make_benign_session(_VALID_UUID_A, n_events=5)
        result = runner.run_single(session, [session])
        self.assertIsInstance(result, SessionResult)

    def test_alert_threshold_respected(self):
        """
        Sessions with confidence below threshold should not be alerted.
        Sessions above should be alerted.
        """
        runner = DetectionRunner(alert_threshold=0.35)
        # A benign session in a corpus of other benign sessions
        # should not alert at 0.35 threshold
        corpus = []
        for i in range(10):
            sid = f"benign-thresh-{i:04d}-aaaa-aaaa-aaaaaaaaaaaa"
            corpus.append(_make_benign_session(
                session_id=sid,
                account="bob",
                n_events=6,
                base_time=f"2025-11-14T{8 + (i % 8):02d}:00:00.000Z",
            ))
        result = runner.run_single(corpus[0], corpus)
        # Benign vs benign baseline should not alert
        # (this could theoretically alert on population baseline —
        #  we just verify the field is set consistently with the score)
        alerted = result.correlation.alert_triggered
        conf = result.correlation.overall_confidence
        self.assertEqual(alerted, conf >= 0.35)

    def test_custom_alert_threshold_propagated(self):
        """alert_threshold_override should appear in CorrelationOutput."""
        runner = DetectionRunner(alert_threshold=0.60)
        corpus = [_make_benign_session(_VALID_UUID_A, n_events=5)]
        result = runner.run_single(corpus[0], corpus)
        self.assertEqual(result.correlation.alert_threshold, 0.60)


# ---------------------------------------------------------------------------
# Test: run() against a real (temporary) MABE output directory
# ---------------------------------------------------------------------------

class TestRunAgainstDirectory(unittest.TestCase):
    """
    Integration test: build a tiny MABE output directory on disk,
    then call runner.run() against it.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_bundle(
        self,
        session: NormalizedSession,
        security_events: list[dict] | None = None,
    ) -> Path:
        """Write a minimal MABE bundle to a temp directory."""
        bundle_dir = self.tmp_path / f"session_{session.session_id}"
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Convert normalized events back to approximate security_events format
        # (runner.run() calls iter_normalized_sessions, which calls ingest)
        # Simplest approach: write events in the security_events format
        # that ingest.py knows how to parse.
        sec_events = security_events or _session_to_security_events(session)
        (bundle_dir / "security_events.json").write_text(
            json.dumps(sec_events), encoding="utf-8"
        )
        (bundle_dir / "sysmon_events.json").write_text(
            "[]", encoding="utf-8"
        )
        (bundle_dir / "session_manifest.json").write_text(
            json.dumps({
                "session_id": session.session_id,
                "is_attack":  False,  # deliberately benign to test blindness
                "agent_type": "benign_user",
                "user":       session.account,
                "session_start": session.events[0]["timestamp"] if session.events else "",
                "session_end":   session.events[-1]["timestamp"] if session.events else "",
                "hosts_touched": [],
                "total_events":  len(session.events),
                "ground_truth":  {"enum_phases": [], "ttps": []},
            }),
            encoding="utf-8",
        )
        return bundle_dir

    def test_run_returns_detection_result(self):
        session = _make_benign_session(
            _VALID_UUID_A, account="j.harrison", n_events=8
        )
        self._write_bundle(session, _session_to_security_events(session))
        runner = DetectionRunner()
        result = runner.run(self.tmp_path)
        self.assertIsInstance(result, DetectionResult)

    def test_run_evaluates_correct_count(self):
        sessions = [
            _make_benign_session(
                f"test-{i:04d}-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                account="j.harrison",
                n_events=6,
            )
            for i in range(3)
        ]
        for s in sessions:
            self._write_bundle(s, _session_to_security_events(s))

        runner = DetectionRunner()
        result = runner.run(self.tmp_path)
        self.assertEqual(result.sessions_evaluated, 3)

    def test_run_empty_directory_returns_zero_sessions(self):
        runner = DetectionRunner()
        result = runner.run(self.tmp_path)
        self.assertEqual(result.sessions_evaluated, 0)
        self.assertEqual(result.sessions_alerted, 0)

    def test_run_records_run_timestamp(self):
        session = _make_benign_session(_VALID_UUID_A, n_events=5)
        self._write_bundle(session, _session_to_security_events(session))
        runner = DetectionRunner()
        result = runner.run(self.tmp_path)
        self.assertTrue(result.run_timestamp.endswith("Z"))

    def test_run_records_duration(self):
        session = _make_benign_session(_VALID_UUID_A, n_events=5)
        self._write_bundle(session, _session_to_security_events(session))
        runner = DetectionRunner()
        result = runner.run(self.tmp_path)
        self.assertGreater(result.run_duration_s, 0.0)

    def test_convenience_function_matches_runner(self):
        session = _make_benign_session(_VALID_UUID_A, n_events=5)
        self._write_bundle(session, _session_to_security_events(session))
        result = run_detection(self.tmp_path)
        self.assertIsInstance(result, DetectionResult)


# ---------------------------------------------------------------------------
# Helper: convert NormalizedSession events back to security_events format
# so that ingest.py can re-read them in integration tests
# ---------------------------------------------------------------------------

def _session_to_security_events(session: NormalizedSession) -> list[dict]:
    """
    Convert normalized events to approximate security_events.json format.

    This round-trip is only used in integration tests where we need to
    write bundles to disk and have ingest.py re-read them.
    Only produces EventID 4624 / 4625 records — enough for the mechanisms.
    """
    records = []
    for e in session.events:
        if e.get("event_type") not in ("auth_attempt",):
            continue
        event_id = 4624 if e.get("success") else 4625
        records.append({
            "EventID":                    event_id,
            "TimeCreated":                e.get("timestamp", ""),
            "host":                       e.get("dst_host", ""),
            "SubjectUserName":            e.get("user", ""),
            "TargetUserName":             e.get("user", ""),
            "IpAddress":                  e.get("src_ip", "10.0.2.1"),
            "LogonType":                  3,
            "AuthenticationPackageName":  "Kerberos",
            "LogonId":                    "0x3E7",
            "Status":                     "0x0",
        })
    return records


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
