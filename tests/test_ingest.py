"""
Tests for sift/ingest.py
========================

Runs without any installed dependencies beyond the standard library.
Does NOT require the core/ package to be importable — ingest.py has
no imports from core.

Run with:
    python -m pytest tests/test_ingest.py -v
or:
    python tests/test_ingest.py   (if running standalone)
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the module under test.
# Adjust the import path to match your project layout.
# If running from detector-sift/:  from sift.ingest import ...
# If running from detector-sift/sift/:  from ingest import ...
# ---------------------------------------------------------------------------
import sys
import os

# Allow running from any working directory by finding ingest.py
_HERE = Path(__file__).parent
for candidate in [_HERE, _HERE.parent / "sift", _HERE / "sift"]:
    if (candidate / "ingest.py").exists():
        sys.path.insert(0, str(candidate))
        break

from ingest import (
    load_session_bundle,
    normalize_session,
    load_and_normalize,
    scan_output_directory,
    iter_normalized_sessions,
    _extract_session_id,
    _normalize_timestamp,
    _infer_port_from_hostname,
    _infer_port_from_auth_package,
    SessionBundle,
    NormalizedSession,
    EVENTID_TO_TYPE,
    EVENTID_SUCCESS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"

SECURITY_EVENTS_MINIMAL = [
    {
        "EventID": 4624,
        "TimeCreated": "2025-11-14T09:00:02.312Z",
        "host": "DC-01",
        "SubjectUserName": "j.harrison",
        "TargetUserName": "j.harrison",
        "IpAddress": "10.0.2.47",
        "LogonType": 3,
        "AuthenticationPackageName": "Kerberos",
        "LogonId": "0x3E7",
        "Status": "0x0",
    },
    {
        "EventID": 4625,
        "TimeCreated": "2025-11-14T09:00:05.100Z",
        "host": "DB-01",
        "SubjectUserName": "j.harrison",
        "TargetUserName": "j.harrison",
        "IpAddress": "10.0.2.47",
        "LogonType": 3,
        "AuthenticationPackageName": "NTLM",
        "LogonId": "0x0",
        "Status": "0xC000006D",
        "FailureReason": "auth_failed",
    },
    {
        "EventID": 4648,
        "TimeCreated": "2025-11-14T09:00:10.000Z",
        "host": "WS-001",
        "SubjectUserName": "j.harrison",
        "TargetServerName": "FS-01",
        "IpAddress": "10.0.2.47",
        "AuthenticationPackageName": "NTLM",
        "LogonId": "0x3E8",
    },
    {
        "EventID": 4768,
        "TimeCreated": "2025-11-14T09:00:15.000Z",
        "host": "DC-01",
        "ClientAddress": "10.0.2.47",
        "TargetUserName": "j.harrison",
        "Status": "0x0",
    },
    {
        "EventID": 4771,
        "TimeCreated": "2025-11-14T09:00:20.000Z",
        "host": "DC-02",
        "ClientAddress": "10.0.2.47",
        "TargetUserName": "j.harrison",
        "Status": "0x18",
    },
]

SYSMON_EVENTS_MINIMAL = [
    {
        "EventID": 3,
        "UtcTime": "2025-11-14T09:00:03.000Z",
        "User": "CORP\\j.harrison",
        "DestinationHostname": "DB-02",
        "DestinationPort": 1433,
        "SourceIp": "10.0.2.47",
        "Image": "python.exe",
        "ProcessId": 1234,
    },
    {
        "EventID": 11,
        "UtcTime": "2025-11-14T09:00:12.000Z",
        "User": "CORP\\j.harrison",
        "host": "FS-01",
        "TargetFilename": "\\\\FS-01\\Finance\\budget.xlsx",
        "Image": "python.exe",
        "ProcessId": 1234,
    },
    {
        "EventID": 22,
        "UtcTime": "2025-11-14T09:00:25.000Z",
        "User": "CORP\\j.harrison",
        "QueryName": "dc-02.corp.local",
        "Image": "python.exe",
        "ProcessId": 1234,
    },
    {
        "EventID": 1,   # ProcessCreate — should be skipped
        "UtcTime": "2025-11-14T09:00:01.000Z",
        "User": "CORP\\j.harrison",
        "Image": "python.exe",
        "ProcessId": 1234,
    },
]

MANIFEST_BENIGN = {
    "session_id": VALID_UUID,
    "is_attack": False,
    "agent_type": "benign_user",
    "user": "j.harrison",
    "session_start": "2025-11-14T09:00:00.000Z",
    "session_end": "2025-11-14T09:01:00.000Z",
    "hosts_touched": ["DC-01", "FS-01"],
    "total_events": 5,
    "ground_truth": {"enum_phases": [], "ttps": []},
}


def _make_bundle_dir(
    tmp_path: Path,
    session_id: str = VALID_UUID,
    security_events: list = None,
    sysmon_events: list = None,
    manifest: dict = None,
) -> Path:
    """Create a temporary MABE session bundle directory."""
    bundle_dir = tmp_path / f"session_{session_id}"
    bundle_dir.mkdir(parents=True)

    sec = security_events if security_events is not None else SECURITY_EVENTS_MINIMAL
    (bundle_dir / "security_events.json").write_text(
        json.dumps(sec), encoding="utf-8"
    )

    sys_ev = sysmon_events if sysmon_events is not None else SYSMON_EVENTS_MINIMAL
    (bundle_dir / "sysmon_events.json").write_text(
        json.dumps(sys_ev), encoding="utf-8"
    )

    mf = manifest if manifest is not None else MANIFEST_BENIGN
    (bundle_dir / "session_manifest.json").write_text(
        json.dumps(mf), encoding="utf-8"
    )

    return bundle_dir


# ---------------------------------------------------------------------------
# Test: session_id extraction
# ---------------------------------------------------------------------------

class TestSessionIdExtraction(unittest.TestCase):

    def test_valid_uuid_directory(self):
        warnings = []
        sid = _extract_session_id(f"session_{VALID_UUID}", warnings)
        self.assertEqual(sid, VALID_UUID)
        self.assertEqual(warnings, [])

    def test_no_prefix_falls_back_to_full_name(self):
        warnings = []
        sid = _extract_session_id("some_other_dir", warnings)
        self.assertEqual(sid, "some_other_dir")
        self.assertEqual(len(warnings), 1)
        self.assertIn("does not match", warnings[0])

    def test_uppercase_uuid_normalised(self):
        upper_uuid = VALID_UUID.upper()
        warnings = []
        sid = _extract_session_id(f"session_{upper_uuid}", warnings)
        self.assertEqual(sid.lower(), VALID_UUID)


# ---------------------------------------------------------------------------
# Test: timestamp normalization
# ---------------------------------------------------------------------------

class TestTimestampNormalization(unittest.TestCase):

    def test_canonical_passthrough(self):
        warnings = []
        ts = _normalize_timestamp("2025-11-14T09:00:02.312Z", 4624, warnings)
        self.assertEqual(ts, "2025-11-14T09:00:02.312Z")
        self.assertEqual(warnings, [])

    def test_no_milliseconds(self):
        warnings = []
        ts = _normalize_timestamp("2025-11-14T09:00:02Z", 4624, warnings)
        self.assertEqual(ts, "2025-11-14T09:00:02.000Z")

    def test_space_separator_with_ms(self):
        warnings = []
        ts = _normalize_timestamp("2025-11-14 09:00:02.312", 4624, warnings)
        self.assertEqual(ts, "2025-11-14T09:00:02.312Z")

    def test_space_separator_no_ms(self):
        warnings = []
        ts = _normalize_timestamp("2025-11-14 09:00:02", 4624, warnings)
        self.assertEqual(ts, "2025-11-14T09:00:02.000Z")

    def test_fractional_seconds_truncated_to_3(self):
        warnings = []
        ts = _normalize_timestamp("2025-11-14 09:00:02.123456", 4624, warnings)
        self.assertEqual(ts, "2025-11-14T09:00:02.123Z")

    def test_unparseable_returns_none_and_warns(self):
        warnings = []
        ts = _normalize_timestamp("not-a-timestamp", 4624, warnings)
        self.assertIsNone(ts)
        self.assertEqual(len(warnings), 1)

    def test_empty_string_returns_none(self):
        warnings = []
        ts = _normalize_timestamp("", 4624, warnings)
        self.assertIsNone(ts)


# ---------------------------------------------------------------------------
# Test: port inference
# ---------------------------------------------------------------------------

class TestPortInference(unittest.TestCase):

    def test_kerberos_package_maps_to_88(self):
        warnings = []
        port = _infer_port_from_auth_package("Kerberos", "", warnings)
        self.assertEqual(port, 88)

    def test_ntlm_package_maps_to_445(self):
        warnings = []
        port = _infer_port_from_auth_package("NTLM", "", warnings)
        self.assertEqual(port, 445)

    def test_hostname_dc_fallback(self):
        warnings = []
        port = _infer_port_from_auth_package("UnknownPackage", "DC-01", warnings)
        self.assertEqual(port, 88)

    def test_hostname_db_fallback(self):
        self.assertEqual(_infer_port_from_hostname("DB-02"), 1433)

    def test_hostname_fs_fallback(self):
        self.assertEqual(_infer_port_from_hostname("FS-01"), 445)

    def test_hostname_ws_fallback(self):
        self.assertEqual(_infer_port_from_hostname("WS-001"), 3389)

    def test_unknown_hostname_returns_zero(self):
        self.assertEqual(_infer_port_from_hostname("MYSTERY-HOST"), 0)

    def test_empty_hostname_returns_zero(self):
        self.assertEqual(_infer_port_from_hostname(""), 0)


# ---------------------------------------------------------------------------
# Test: load_session_bundle
# ---------------------------------------------------------------------------

class TestLoadSessionBundle(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_loads_valid_bundle(self):
        bundle_dir = _make_bundle_dir(self.tmp_path)
        bundle = load_session_bundle(bundle_dir)

        self.assertEqual(bundle.session_id, VALID_UUID)
        self.assertEqual(len(bundle.security_events), len(SECURITY_EVENTS_MINIMAL))
        self.assertEqual(len(bundle.sysmon_events), len(SYSMON_EVENTS_MINIMAL))
        self.assertEqual(bundle.account, "j.harrison")

    def test_missing_directory_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_session_bundle(self.tmp_path / "nonexistent")

    def test_missing_security_events_raises(self):
        bundle_dir = self.tmp_path / f"session_{VALID_UUID}"
        bundle_dir.mkdir()
        # Only create manifest, omit security_events.json
        (bundle_dir / "session_manifest.json").write_text(
            json.dumps(MANIFEST_BENIGN)
        )
        with self.assertRaises(ValueError):
            load_session_bundle(bundle_dir)

    def test_missing_sysmon_is_not_error(self):
        bundle_dir = self.tmp_path / f"session_{VALID_UUID}"
        bundle_dir.mkdir()
        (bundle_dir / "security_events.json").write_text(
            json.dumps(SECURITY_EVENTS_MINIMAL)
        )
        (bundle_dir / "session_manifest.json").write_text(
            json.dumps(MANIFEST_BENIGN)
        )
        bundle = load_session_bundle(bundle_dir)
        self.assertEqual(bundle.sysmon_events, [])

    def test_is_attack_not_read_from_manifest(self):
        """Verify ground-truth blindness: is_attack must not appear on bundle."""
        bundle_dir = _make_bundle_dir(
            self.tmp_path,
            manifest={**MANIFEST_BENIGN, "is_attack": True}
        )
        bundle = load_session_bundle(bundle_dir)
        # SessionBundle has no is_attack attribute — confirm via hasattr
        self.assertFalse(hasattr(bundle, "is_attack"))

    def test_empty_security_events_file(self):
        bundle_dir = self.tmp_path / f"session_{VALID_UUID}"
        bundle_dir.mkdir()
        (bundle_dir / "security_events.json").write_text("[]")
        (bundle_dir / "session_manifest.json").write_text(json.dumps(MANIFEST_BENIGN))
        bundle = load_session_bundle(bundle_dir)
        self.assertEqual(bundle.security_events, [])

    def test_json_lines_format(self):
        """security_events.json as JSON Lines (one object per line)."""
        bundle_dir = self.tmp_path / f"session_{VALID_UUID}"
        bundle_dir.mkdir()
        jl = "\n".join(json.dumps(e) for e in SECURITY_EVENTS_MINIMAL)
        (bundle_dir / "security_events.json").write_text(jl)
        (bundle_dir / "session_manifest.json").write_text(json.dumps(MANIFEST_BENIGN))
        bundle = load_session_bundle(bundle_dir)
        self.assertEqual(len(bundle.security_events), len(SECURITY_EVENTS_MINIMAL))


# ---------------------------------------------------------------------------
# Test: normalize_session — security events
# ---------------------------------------------------------------------------

class TestNormalizeSecurityEvents(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _normalized(self, security_events=None, sysmon_events=None):
        bundle_dir = _make_bundle_dir(
            self.tmp_path,
            security_events=security_events or SECURITY_EVENTS_MINIMAL,
            sysmon_events=sysmon_events or [],
        )
        bundle = load_session_bundle(bundle_dir)
        return normalize_session(bundle)

    def test_all_required_fields_present(self):
        session = self._normalized()
        required = {"timestamp", "session_id", "user", "event_type",
                    "dst_host", "dst_port", "success"}
        for event in session.events:
            missing = required - set(event.keys())
            self.assertEqual(
                missing, set(),
                f"Event missing fields {missing}: {event}"
            )

    def test_4624_maps_to_auth_attempt_success_true(self):
        session = self._normalized()
        ev4624 = [e for e in session.events if e.get("_event_id") == 4624]
        self.assertTrue(len(ev4624) >= 1)
        self.assertEqual(ev4624[0]["event_type"], "auth_attempt")
        self.assertTrue(ev4624[0]["success"])

    def test_4625_maps_to_auth_attempt_success_false(self):
        session = self._normalized()
        ev4625 = [e for e in session.events if e.get("_event_id") == 4625]
        self.assertTrue(len(ev4625) >= 1)
        self.assertEqual(ev4625[0]["event_type"], "auth_attempt")
        self.assertFalse(ev4625[0]["success"])

    def test_4648_uses_target_server_name_as_dst_host(self):
        session = self._normalized()
        ev4648 = [e for e in session.events if e.get("_event_id") == 4648]
        self.assertTrue(len(ev4648) >= 1)
        self.assertEqual(ev4648[0]["dst_host"], "FS-01")

    def test_4768_maps_to_kerberos_tgt_request(self):
        session = self._normalized()
        ev4768 = [e for e in session.events if e.get("_event_id") == 4768]
        self.assertTrue(len(ev4768) >= 1)
        self.assertEqual(ev4768[0]["event_type"], "kerberos_tgt_request")
        self.assertTrue(ev4768[0]["success"])

    def test_4771_maps_to_kerberos_tgt_request_failure(self):
        session = self._normalized()
        ev4771 = [e for e in session.events if e.get("_event_id") == 4771]
        self.assertTrue(len(ev4771) >= 1)
        self.assertEqual(ev4771[0]["event_type"], "kerberos_tgt_request")
        self.assertFalse(ev4771[0]["success"])

    def test_domain_prefix_stripped_from_user(self):
        events = [{
            **SECURITY_EVENTS_MINIMAL[0],
            "SubjectUserName": "CORP\\j.harrison",
        }]
        session = self._normalized(security_events=events)
        users = {e["user"] for e in session.events if e.get("user")}
        self.assertNotIn("CORP\\j.harrison", users)
        self.assertIn("j.harrison", users)

    def test_kerberos_auth_infers_port_88(self):
        ev = [SECURITY_EVENTS_MINIMAL[0]]  # 4624 with Kerberos pkg, host DC-01
        session = self._normalized(security_events=ev)
        sec_events = [e for e in session.events if e.get("_source") == "security"]
        self.assertEqual(len(sec_events), 1)
        self.assertEqual(sec_events[0]["dst_port"], 88)

    def test_session_id_stamped_on_all_events(self):
        session = self._normalized()
        for event in session.events:
            self.assertEqual(event["session_id"], VALID_UUID)

    def test_events_sorted_chronologically(self):
        session = self._normalized()
        timestamps = [e["timestamp"] for e in session.events]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_unknown_event_id_skipped(self):
        events = [
            {"EventID": 9999, "TimeCreated": "2025-11-14T09:00:00.000Z",
             "host": "DC-01", "SubjectUserName": "user"},
            *SECURITY_EVENTS_MINIMAL[:1],
        ]
        session = self._normalized(security_events=events)
        event_ids = {e.get("_event_id") for e in session.events}
        self.assertNotIn(9999, event_ids)

    def test_missing_timestamp_skipped_with_warning(self):
        events = [
            {**SECURITY_EVENTS_MINIMAL[0], "TimeCreated": ""},
        ]
        session = self._normalized(security_events=events)
        self.assertEqual(len(session.events), 0)
        self.assertTrue(len(session.load_warnings) > 0)


# ---------------------------------------------------------------------------
# Test: normalize_session — sysmon events
# ---------------------------------------------------------------------------

class TestNormalizeSysmonEvents(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _normalized(self, sysmon_events=None):
        bundle_dir = _make_bundle_dir(
            self.tmp_path,
            security_events=[],
            sysmon_events=sysmon_events or SYSMON_EVENTS_MINIMAL,
        )
        bundle = load_session_bundle(bundle_dir)
        return normalize_session(bundle)

    def test_sysmon_3_maps_to_network_connection(self):
        session = self._normalized()
        ev3 = [e for e in session.events if e.get("_event_id") == 3]
        self.assertTrue(len(ev3) >= 1)
        self.assertEqual(ev3[0]["event_type"], "network_connection")
        self.assertEqual(ev3[0]["dst_host"], "DB-02")
        self.assertEqual(ev3[0]["dst_port"], 1433)

    def test_sysmon_11_maps_to_file_access(self):
        session = self._normalized()
        ev11 = [e for e in session.events if e.get("_event_id") == 11]
        self.assertTrue(len(ev11) >= 1)
        self.assertEqual(ev11[0]["event_type"], "file_access")
        self.assertEqual(ev11[0]["dst_host"], "FS-01")
        self.assertEqual(ev11[0]["object_name"], "\\\\FS-01\\Finance\\budget.xlsx")

    def test_sysmon_22_maps_to_dns_query(self):
        session = self._normalized()
        ev22 = [e for e in session.events if e.get("_event_id") == 22]
        self.assertTrue(len(ev22) >= 1)
        self.assertEqual(ev22[0]["event_type"], "dns_query")
        self.assertEqual(ev22[0]["dst_host"], "dc-02.corp.local")
        self.assertEqual(ev22[0]["dst_port"], 53)

    def test_sysmon_1_is_skipped(self):
        """ProcessCreate events (Event 1) should be silently skipped."""
        session = self._normalized()
        ev1 = [e for e in session.events if e.get("_event_id") == 1]
        self.assertEqual(ev1, [])

    def test_domain_prefix_stripped_from_sysmon_user(self):
        session = self._normalized()
        users = {e["user"] for e in session.events if e.get("user")}
        self.assertNotIn("CORP\\j.harrison", users)
        self.assertIn("j.harrison", users)

    def test_file_access_port_inferred_from_fs_hostname(self):
        session = self._normalized()
        ev11 = [e for e in session.events if e.get("_event_id") == 11]
        self.assertEqual(ev11[0]["dst_port"], 445)

    def test_sysmon_success_is_always_true(self):
        """Sysmon records only log what happened — no failure records."""
        session = self._normalized()
        for e in session.events:
            if e.get("_source") == "sysmon":
                self.assertTrue(e["success"])


# ---------------------------------------------------------------------------
# Test: scan_output_directory and iter_normalized_sessions
# ---------------------------------------------------------------------------

class TestScanOutputDirectory(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_output_dir(self, n_sessions: int) -> Path:
        output_dir = self.tmp_path / "sift"
        output_dir.mkdir()
        uuids = [
            f"550e8400-e29b-41d4-a716-{i:012d}"
            for i in range(n_sessions)
        ]
        for uuid in uuids:
            _make_bundle_dir(output_dir, session_id=uuid)
        return output_dir

    def test_finds_all_bundles(self):
        output_dir = self._make_output_dir(5)
        bundles = scan_output_directory(output_dir)
        self.assertEqual(len(bundles), 5)

    def test_returns_sorted_paths(self):
        output_dir = self._make_output_dir(3)
        bundles = scan_output_directory(output_dir)
        names = [b.name for b in bundles]
        self.assertEqual(names, sorted(names))

    def test_skips_non_session_directories(self):
        output_dir = self._make_output_dir(2)
        (output_dir / "some_other_dir").mkdir()
        (output_dir / "reports").mkdir()
        bundles = scan_output_directory(output_dir)
        self.assertEqual(len(bundles), 2)

    def test_skips_session_dir_without_security_events(self):
        output_dir = self.tmp_path / "sift"
        output_dir.mkdir()
        # Valid bundle
        _make_bundle_dir(output_dir, session_id=VALID_UUID)
        # Incomplete bundle — missing security_events.json
        bad_dir = output_dir / "session_baad0000-0000-0000-0000-000000000000"
        bad_dir.mkdir()
        bundles = scan_output_directory(output_dir)
        self.assertEqual(len(bundles), 1)

    def test_nonexistent_dir_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_output_directory(self.tmp_path / "nonexistent")

    def test_iter_yields_normalized_sessions(self):
        output_dir = self._make_output_dir(3)
        sessions = list(iter_normalized_sessions(output_dir))
        self.assertEqual(len(sessions), 3)
        for s in sessions:
            self.assertIsInstance(s, NormalizedSession)
            self.assertTrue(len(s.events) > 0)

    def test_iter_skips_bad_bundle_without_crashing(self):
        output_dir = self.tmp_path / "sift"
        output_dir.mkdir()
        # Valid bundle
        _make_bundle_dir(output_dir, session_id=VALID_UUID)
        # Corrupt bundle — invalid JSON
        bad_dir = output_dir / "session_baad0000-0000-0000-0000-000000000000"
        bad_dir.mkdir()
        (bad_dir / "security_events.json").write_text("NOT JSON {{{{")
        (bad_dir / "session_manifest.json").write_text(json.dumps(MANIFEST_BENIGN))
        # Should yield only the valid session, not crash
        sessions = list(iter_normalized_sessions(output_dir))
        self.assertEqual(len(sessions), 1)


# ---------------------------------------------------------------------------
# Test: combined security + sysmon session
# ---------------------------------------------------------------------------

class TestCombinedSession(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_combined_event_count(self):
        """Security + sysmon events both appear in normalized output."""
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)

        security_count = len([
            e for e in session.events if e.get("_source") == "security"
        ])
        sysmon_count = len([
            e for e in session.events if e.get("_source") == "sysmon"
        ])

        # 5 security events, EventID 9999 is not in our table so all 5 map
        # Sysmon: 4 records, EventID 1 (ProcessCreate) is skipped → 3 events
        self.assertEqual(security_count, 5)
        self.assertEqual(sysmon_count, 3)
        self.assertEqual(len(session.events), 8)

    def test_priv_esc_mechanism_fields_present(self):
        """
        Events used by PrivEscMechanism must have required fields.
        Specifically: auth_attempt events need success, dst_host, dst_port.
        """
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)

        auth_events = [
            e for e in session.events
            if e.get("event_type") in (
                "auth_attempt", "kerberos_tgt_request", "kerberos_ticket_request"
            )
        ]
        for e in auth_events:
            self.assertIn("success", e, f"success missing: {e}")
            self.assertIn("dst_host", e, f"dst_host missing: {e}")
            self.assertIn("dst_port", e, f"dst_port missing: {e}")

    def test_enumeration_mechanism_fields_present(self):
        """
        Events used by EnumerationMechanism: dst_host must be non-empty
        for the events that contribute to destination count.
        """
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)

        # At least some events should have a non-empty dst_host
        dsts = {e.get("dst_host") for e in session.events if e.get("dst_host")}
        self.assertTrue(len(dsts) > 0, "No dst_host values found in session")

    def test_velocity_mechanism_fields_present(self):
        """
        Velocity mechanism only needs timestamps.
        All events must have a non-empty timestamp.
        """
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)

        for e in session.events:
            self.assertIn("timestamp", e)
            self.assertTrue(e["timestamp"], f"Empty timestamp on event: {e}")

    def test_account_set_on_session(self):
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)
        self.assertEqual(session.account, "j.harrison")

    def test_no_label_fields_in_events(self):
        """
        Normalized events must not carry any ground-truth label fields.
        These would leak is_attack information to the mechanisms.
        """
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)

        forbidden_fields = {"is_attack", "enum_phase", "attack_step", "ttp"}
        for e in session.events:
            leaked = forbidden_fields & set(e.keys())
            self.assertEqual(
                leaked, set(),
                f"Event leaked ground-truth fields {leaked}: {e}"
            )


# ---------------------------------------------------------------------------
# Test: edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_security_events_produces_empty_session(self):
        bundle_dir = _make_bundle_dir(
            self.tmp_path, security_events=[], sysmon_events=[]
        )
        session = load_and_normalize(bundle_dir)
        self.assertEqual(session.events, [])

    def test_manifest_without_user_falls_back_to_event_inference(self):
        manifest_no_user = {**MANIFEST_BENIGN, "user": ""}
        bundle_dir = _make_bundle_dir(
            self.tmp_path, manifest=manifest_no_user
        )
        session = load_and_normalize(bundle_dir)
        # Account should be inferred from the event records
        self.assertEqual(session.account, "j.harrison")

    def test_logon_id_preserved_for_evidence_tracing(self):
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)
        ev4624 = [e for e in session.events if e.get("_event_id") == 4624]
        self.assertEqual(ev4624[0].get("logon_id"), "0x3E7")

    def test_process_name_preserved_on_sysmon_events(self):
        bundle_dir = _make_bundle_dir(self.tmp_path)
        session = load_and_normalize(bundle_dir)
        net_events = [e for e in session.events if e.get("_event_id") == 3]
        self.assertEqual(net_events[0].get("process_name"), "python.exe")

    def test_duplicate_events_not_deduplicated(self):
        """
        Ingest does not deduplicate events. The mechanisms see every
        record that was in the source files. Deduplication is out of
        scope for ingestion.
        """
        doubled = SECURITY_EVENTS_MINIMAL + SECURITY_EVENTS_MINIMAL
        bundle_dir = _make_bundle_dir(self.tmp_path, security_events=doubled)
        session = load_and_normalize(bundle_dir)
        sec_events = [e for e in session.events if e.get("_source") == "security"]
        self.assertEqual(len(sec_events), len(SECURITY_EVENTS_MINIMAL) * 2)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
