"""
MABE Detector — SIFT Ingestion Adapter
========================================
Version: 1.0.0

Reads MABE session bundle directories and converts their label-free
event files into the normalized event format the core detection
mechanisms expect.

WHAT A MABE BUNDLE CONTAINS
-----------------------------
output/sift/session_{uuid}/
    security_events.json    ← Windows Security Events (label-free)
    sysmon_events.json      ← Sysmon records (label-free)
    session_manifest.json   ← Ground truth labels (NOT read by detector)

The two event files are intentionally label-free — no is_attack,
enum_phase, or ttp fields. The detector must find the evil purely
from behavioral analysis, as it would in a real deployment.

WHAT THE CORE MECHANISMS NEED
------------------------------
Each mechanism receives a list of event dicts. Required fields per
mechanism:

    All mechanisms:
        timestamp   str     ISO 8601 with millisecond precision + Z suffix
        session_id  str     UUID (inferred from bundle directory name)
        user        str     Account identifier

    Velocity (timestamps only — no extra fields required beyond above)

    Enumeration:
        dst_host    str     Destination hostname
        dst_port    int     Destination port (for node type inference)
        event_type  str     One of the canonical MABE event type strings

    Privilege escalation:
        event_type  str     "auth_attempt", "file_access", "kerberos_tgt_request"
        success     bool    Whether the action succeeded
        dst_host    str     Destination hostname
        dst_port    int     Destination port (for node type inference)

FIELD MAPPING STRATEGY
-----------------------
security_events.json uses EVTX-style field names. The mapping is:

    EVTX field          → Core field         Notes
    ──────────────────────────────────────────────────────────────────
    TimeCreated         → timestamp          Direct
    SubjectUserName     → user               Falls back to TargetUserName
    host                → dst_host           The host the event was recorded on
    EventID             → event_type         See EVENTID_TO_TYPE table
    EventID             → success            See EVENTID_SUCCESS table
    port (inferred)     → dst_port           Inferred from EventID + protocol
    LogonId             → logon_id           Preserved for evidence tracing
    AuthenticationPackageName → protocol     Mapped back to protocol string

sysmon_events.json uses Sysmon field names:

    Sysmon field        → Core field         Notes
    ──────────────────────────────────────────────────────────────────
    UtcTime             → timestamp          Direct
    User                → user               Direct
    DestinationHostname → dst_host           Event 3 (NetworkConnect)
    DestinationPort     → dst_port           Event 3 (NetworkConnect)
    Image               → process_name       Events 1, 3
    ProcessId           → process_id         Events 1, 3
    TargetFilename      → object_name        Event 11 (FileCreate)

EVENTID MAPPING RATIONALE
--------------------------
The MABE evtx_json.py formatter produces a specific subset of Event IDs.
This table maps exactly those IDs — no others need handling:

    4624  Successful logon         → auth_attempt, success=True
    4625  Failed logon             → auth_attempt, success=False
    4648  Explicit credential use  → auth_attempt (src-side), success depends
          on whether a 4624 follows; treated as success=True for now
          since MABE only emits 4648 alongside successful auth flows.
    4768  Kerberos TGT request     → kerberos_tgt_request
    4769  Kerberos service ticket  → kerberos_ticket_request
    4771  Kerberos pre-auth failed → kerberos_tgt_request, success=False

Sysmon Event IDs:
    1     ProcessCreate            → skipped (no dst_host / timing only)
    3     NetworkConnect           → network_connection
    7     ImageLoad                → skipped (not needed by mechanisms)
    11    FileCreate               → file_access
    13    RegistryValueSet         → registry_access
    22    DNSQuery                 → dns_query

PORT INFERENCE
--------------
MABE's security_events.json does not carry dst_port directly (Windows
Security Events don't include service port in logon records). Port is
inferred from the authentication package / protocol field:

    Kerberos auth → port 88  (domain_controller)
    LDAP / NTLM   → port 389 (domain_controller fallback)
    MSSQL         → port 1433
    PostgreSQL     → port 5432
    SMB / CIFS    → port 445 (file_server / workstation)
    HTTP          → port 80
    HTTPS         → port 443
    RDP           → port 3389

When port cannot be inferred (generic NTLM, Negotiate, etc.) and the
destination host contains a recognizable node type hint in its name
(e.g. "DC-01", "DB-03"), name-based heuristics supplement the mapping.
When all else fails, port defaults to 0 (classified as "unknown" by
NodeClassifier, which is fine — it simply won't contribute to node type
signals).

GROUND TRUTH ISOLATION
-----------------------
session_manifest.json is read ONLY to extract the session_id (for
cross-referencing in reports) and the user account (when it cannot be
inferred from event records). The is_attack field is deliberately NOT
read — detection must be blind to ground truth. The manifest is passed
through to SessionBundle.manifest_path so callers can do post-hoc
accuracy scoring separately.

SESSION_ID EXTRACTION
---------------------
session_id is extracted from the bundle directory name:
    "session_550e8400-e29b-41d4-a716-446655440000"
    → "550e8400-e29b-41d4-a716-446655440000"

If the directory does not follow this convention, the full directory
name is used as the session_id with a warning logged.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants: EventID → canonical event_type
# ---------------------------------------------------------------------------

# Maps Windows Security Event IDs to the core mechanism event_type strings.
# Only Event IDs produced by MABE's evtx_json.py formatter are listed.
EVENTID_TO_TYPE: dict[int, str] = {
    4624: "auth_attempt",           # Successful logon
    4625: "auth_attempt",           # Failed logon
    4648: "auth_attempt",           # Explicit credentials (src-side)
    4768: "kerberos_tgt_request",   # Kerberos TGT request
    4769: "kerberos_ticket_request", # Kerberos service ticket
    4771: "kerberos_tgt_request",   # Kerberos pre-auth failed
}

# Maps EventID → success boolean.
# 4648 is emitted by MABE alongside successful auth flows (src-side record).
EVENTID_SUCCESS: dict[int, bool] = {
    4624: True,
    4625: False,
    4648: True,
    4768: True,
    4769: True,
    4771: False,
}

# Maps Sysmon EventIDs to core event_type strings.
SYSMON_EVENTID_TO_TYPE: dict[int, str] = {
    3:  "network_connection",
    11: "file_access",
    13: "registry_access",
    22: "dns_query",
}

# Sysmon Event IDs to skip entirely (not used by any mechanism).
SYSMON_SKIP_IDS: frozenset[int] = frozenset({1, 7})

# ---------------------------------------------------------------------------
# Port inference: AuthenticationPackageName / protocol → dst_port
# ---------------------------------------------------------------------------

# Maps the AuthenticationPackageName field (as written by MABE's evtx formatter)
# to a likely destination port. Used when dst_port is not directly available.
AUTH_PACKAGE_TO_PORT: dict[str, int] = {
    "Kerberos":  88,
    "kerberos":  88,
    "NTLM":      445,   # SMB / NTLM — file_server / workstation
    "Negotiate": 389,   # Generic negotiate → LDAP fallback
    "MSSQL":     1433,
    "mssql":     1433,
    "PostgreSQL": 5432,
    "postgresql": 5432,
    "smb":       445,
    "nfs":       2049,
    "rdp":       3389,
    "http":      80,
    "HTTP":      80,
    "https":     443,
    "HTTPS":     443,
    "oauth":     443,
    "token":     443,
    "basic":     80,
    "sql_auth":  1433,
    "windows_auth": 445,
    "ldap":      389,
    "LDAP":      389,
}

# Hostname prefix patterns → likely dst_port.
# Supplements auth-package inference when the host name carries a type hint.
# Patterns are matched case-insensitively against the start of the hostname.
HOSTNAME_PREFIX_TO_PORT: list[tuple[str, int]] = [
    ("dc",  88),    # DC-01, dc-02 → domain controller → Kerberos
    ("db",  1433),  # DB-01, db-02 → database → MSSQL
    ("fs",  445),   # FS-01        → file server → SMB
    ("reg", 5000),  # REG-01       → container registry
    ("log", 9200),  # LOG-01       → logging infrastructure → Elasticsearch
    ("api", 443),   # API-01       → api endpoint → HTTPS
    ("ws",  3389),  # WS-001       → workstation → RDP
]

# ---------------------------------------------------------------------------
# SessionBundle — lightweight container for one session's raw data
# ---------------------------------------------------------------------------

@dataclass
class SessionBundle:
    """
    Raw data for one MABE session bundle, before normalization.

    Attributes
    ----------
    session_id : str
        UUID extracted from the bundle directory name.
    bundle_dir : Path
        Absolute path to the session bundle directory.
    manifest_path : Path
        Path to session_manifest.json (ground truth — read only for
        session_id and user; is_attack is deliberately not accessed
        by the detector).
    security_events : list[dict]
        Raw records from security_events.json.
    sysmon_events : list[dict]
        Raw records from sysmon_events.json.
    account : str
        Primary user account for this session, extracted from events
        or manifest metadata (non-attack fields only).
    load_warnings : list[str]
        Non-fatal issues encountered during loading (e.g. malformed
        records skipped, port inference fallbacks used).
    """
    session_id:       str
    bundle_dir:       Path
    manifest_path:    Path
    security_events:  list[dict] = field(default_factory=list)
    sysmon_events:    list[dict] = field(default_factory=list)
    account:          str = ""
    load_warnings:    list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Normalized session — what the detection runner receives
# ---------------------------------------------------------------------------

@dataclass
class NormalizedSession:
    """
    A fully normalized session ready for mechanism evaluation.

    Attributes
    ----------
    session_id : str
    account : str
    bundle_dir : Path
        Points back to the original bundle for session_ref in reports.
    events : list[dict]
        Normalized events. Each dict contains at minimum:
            timestamp   str
            session_id  str
            user        str
            event_type  str
            dst_host    str
            dst_port    int
            success     bool
        Plus optional fields preserved from source records:
            logon_id, process_id, process_name, object_name,
            protocol, src_host, src_ip, bytes_in, bytes_out
    load_warnings : list[str]
        Propagated from SessionBundle.
    """
    session_id:    str
    account:       str
    bundle_dir:    Path
    events:        list[dict] = field(default_factory=list)
    load_warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_session_bundle(bundle_dir: Path | str) -> SessionBundle:
    """
    Load raw event files from a single MABE session bundle directory.

    Does NOT normalize — call normalize_session() on the result.
    Splitting load from normalize lets callers inspect raw data and
    makes unit testing each step independently straightforward.

    Parameters
    ----------
    bundle_dir : Path | str
        Path to a directory named "session_{uuid}" containing
        security_events.json, sysmon_events.json, and
        session_manifest.json.

    Returns
    -------
    SessionBundle

    Raises
    ------
    FileNotFoundError
        If bundle_dir does not exist.
    ValueError
        If security_events.json is missing or unreadable.
    """
    bundle_dir = Path(bundle_dir)
    if not bundle_dir.exists():
        raise FileNotFoundError(f"Bundle directory not found: {bundle_dir}")

    warnings: list[str] = []

    # ── Extract session_id from directory name ─────────────────────────
    session_id = _extract_session_id(bundle_dir.name, warnings)

    # ── Load security_events.json (required) ──────────────────────────
    sec_path = bundle_dir / "security_events.json"
    if not sec_path.exists():
        raise ValueError(
            f"security_events.json not found in {bundle_dir}. "
            "Is this a valid MABE session bundle?"
        )
    security_events = _load_json_list(sec_path, "security_events", warnings)

    # ── Load sysmon_events.json (optional — benign sessions may be empty) ─
    sys_path = bundle_dir / "sysmon_events.json"
    sysmon_events: list[dict] = []
    if sys_path.exists():
        sysmon_events = _load_json_list(sys_path, "sysmon_events", warnings)

    # ── Read manifest for account only — not is_attack ─────────────────
    manifest_path = bundle_dir / "session_manifest.json"
    account = _extract_account_from_manifest(manifest_path, warnings)

    return SessionBundle(
        session_id=session_id,
        bundle_dir=bundle_dir,
        manifest_path=manifest_path,
        security_events=security_events,
        sysmon_events=sysmon_events,
        account=account,
        load_warnings=warnings,
    )


def normalize_session(bundle: SessionBundle) -> NormalizedSession:
    """
    Convert a raw SessionBundle into a NormalizedSession.

    Maps EVTX-style and Sysmon-style fields to the core mechanism
    format. Infers dst_port and event_type from EventID. Infers
    session_id from bundle directory name.

    Parameters
    ----------
    bundle : SessionBundle

    Returns
    -------
    NormalizedSession
    """
    warnings = list(bundle.load_warnings)
    normalized_events: list[dict] = []

    # ── Normalize security events ──────────────────────────────────────
    for raw in bundle.security_events:
        event = _normalize_security_event(raw, bundle.session_id, warnings)
        if event is not None:
            normalized_events.append(event)

    # ── Normalize sysmon events ────────────────────────────────────────
    for raw in bundle.sysmon_events:
        event = _normalize_sysmon_event(raw, bundle.session_id, warnings)
        if event is not None:
            normalized_events.append(event)

    # ── Resolve account if not set by manifest ────────────────────────
    account = bundle.account
    if not account and normalized_events:
        account = _infer_account_from_events(normalized_events)
        if account:
            warnings.append(
                f"account inferred from events (manifest had none): {account}"
            )

    # ── Stamp session_id and account onto every event ─────────────────
    for event in normalized_events:
        event["session_id"] = bundle.session_id
        if account and not event.get("user"):
            event["user"] = account

    # Sort chronologically — mechanisms expect any order but some
    # (priv_esc) sort internally; doing it once here is cleaner.
    normalized_events.sort(key=lambda e: e.get("timestamp", ""))

    return NormalizedSession(
        session_id=bundle.session_id,
        account=account,
        bundle_dir=bundle.bundle_dir,
        events=normalized_events,
        load_warnings=warnings,
    )


def load_and_normalize(bundle_dir: Path | str) -> NormalizedSession:
    """
    Convenience wrapper: load_session_bundle → normalize_session.

    Parameters
    ----------
    bundle_dir : Path | str

    Returns
    -------
    NormalizedSession
    """
    bundle = load_session_bundle(bundle_dir)
    return normalize_session(bundle)


def scan_output_directory(sift_output_dir: Path | str) -> list[Path]:
    """
    Discover all MABE session bundle directories under a SIFT output root.

    Looks for immediate subdirectories named "session_*" containing
    security_events.json. Non-matching directories are silently skipped.

    Parameters
    ----------
    sift_output_dir : Path | str
        Path to MABE's output/sift/ directory.

    Returns
    -------
    list[Path]
        Sorted list of bundle directory paths.

    Raises
    ------
    FileNotFoundError
        If sift_output_dir does not exist.
    """
    sift_output_dir = Path(sift_output_dir)
    if not sift_output_dir.exists():
        raise FileNotFoundError(
            f"SIFT output directory not found: {sift_output_dir}"
        )

    bundles: list[Path] = []
    for entry in sorted(sift_output_dir.iterdir()):
        if not entry.is_dir():
            continue
        if not entry.name.startswith("session_"):
            continue
        if not (entry / "security_events.json").exists():
            logger.debug("Skipping %s — no security_events.json", entry.name)
            continue
        bundles.append(entry)

    logger.info(
        "Found %d session bundles in %s", len(bundles), sift_output_dir
    )
    return bundles


def iter_normalized_sessions(
    sift_output_dir: Path | str,
    *,
    skip_empty: bool = True,
) -> Iterator[NormalizedSession]:
    """
    Iterate over all normalized sessions in a SIFT output directory.

    Yields one NormalizedSession per bundle. Bundles that fail to load
    are logged as errors and skipped — one bad bundle never aborts the
    full dataset run.

    Parameters
    ----------
    sift_output_dir : Path | str
    skip_empty : bool
        If True (default), skip sessions with zero normalized events.
        These cannot be evaluated by any mechanism.

    Yields
    ------
    NormalizedSession
    """
    bundle_dirs = scan_output_directory(sift_output_dir)

    for bundle_dir in bundle_dirs:
        try:
            session = load_and_normalize(bundle_dir)
        except Exception as exc:
            logger.error(
                "Failed to load bundle %s: %s — skipping",
                bundle_dir.name, exc
            )
            continue

        if skip_empty and not session.events:
            logger.warning(
                "Session %s has no normalized events — skipping",
                session.session_id
            )
            continue

        if session.load_warnings:
            logger.debug(
                "Session %s loaded with %d warning(s): %s",
                session.session_id,
                len(session.load_warnings),
                "; ".join(session.load_warnings[:3]),
            )

        yield session


# ---------------------------------------------------------------------------
# Security event normalization
# ---------------------------------------------------------------------------

def _normalize_security_event(
    raw: dict,
    session_id: str,
    warnings: list[str],
) -> dict | None:
    """
    Map one raw security event record to the core event format.

    Returns None for records that should be skipped (unknown EventID,
    missing timestamp, 4648 src-side duplicates when 4624 is present).
    """
    event_id = _coerce_int(raw.get("EventID"))
    if event_id is None:
        warnings.append(f"security event missing EventID — skipped: {_snip(raw)}")
        return None

    event_type = EVENTID_TO_TYPE.get(event_id)
    if event_type is None:
        # EventID not produced by MABE — silently skip
        return None

    timestamp = raw.get("TimeCreated", "")
    if not timestamp:
        warnings.append(
            f"EventID {event_id} missing TimeCreated — skipped"
        )
        return None

    # ── Ensure ISO 8601 Z-suffix format ───────────────────────────────
    timestamp = _normalize_timestamp(timestamp, event_id, warnings)
    if timestamp is None:
        return None

    # ── User resolution ───────────────────────────────────────────────
    # SubjectUserName is the acting account; TargetUserName is the
    # account being authenticated AS. For MABE events, they are the
    # same. Prefer SubjectUserName; fall back to TargetUserName.
    user = (
        raw.get("SubjectUserName")
        or raw.get("TargetUserName")
        or ""
    )
    # Strip domain prefix if present (e.g. "DOMAIN\\j.harrison" → "j.harrison")
    if "\\" in user:
        user = user.split("\\", 1)[1]

    # ── Destination host ──────────────────────────────────────────────
    # For security events, "host" is the machine the event was recorded on.
    # For dst-side events (4624, 4625, 4769, 4771, 4768): host IS the
    # destination being accessed.
    # For src-side events (4648): host is the source; TargetServerName
    # is the destination.
    if event_id == 4648:
        dst_host = raw.get("TargetServerName") or raw.get("host", "")
    else:
        dst_host = raw.get("host", "")

    # ── Source host / IP ──────────────────────────────────────────────
    src_ip = raw.get("IpAddress", "")
    src_host = ""  # security events don't carry src_host separately

    # ── Protocol from AuthenticationPackageName ───────────────────────
    auth_pkg = raw.get("AuthenticationPackageName", "")
    protocol = _auth_package_to_protocol(auth_pkg)

    # ── dst_port inference ────────────────────────────────────────────
    dst_port = _infer_port_from_auth_package(auth_pkg, dst_host, warnings)

    # ── success ───────────────────────────────────────────────────────
    success = EVENTID_SUCCESS.get(event_id, False)

    # ── logon_id ──────────────────────────────────────────────────────
    logon_id = raw.get("LogonId")
    logon_type = _coerce_int(raw.get("LogonType"))

    return {
        "timestamp":   timestamp,
        "session_id":  session_id,
        "user":        user,
        "event_type":  event_type,
        "dst_host":    dst_host,
        "dst_port":    dst_port,
        "src_host":    src_host,
        "src_ip":      src_ip,
        "protocol":    protocol,
        "success":     success,
        "logon_id":    logon_id,
        "logon_type":  logon_type,
        # Preserve raw EventID for evidence tracing in reports
        "_event_id":   event_id,
        "_source":     "security",
    }


# ---------------------------------------------------------------------------
# Sysmon event normalization
# ---------------------------------------------------------------------------

def _normalize_sysmon_event(
    raw: dict,
    session_id: str,
    warnings: list[str],
) -> dict | None:
    """
    Map one raw Sysmon event record to the core event format.

    Returns None for event IDs that carry no mechanism-relevant data.
    """
    event_id = _coerce_int(raw.get("EventID"))
    if event_id is None:
        return None

    if event_id in SYSMON_SKIP_IDS:
        return None

    event_type = SYSMON_EVENTID_TO_TYPE.get(event_id)
    if event_type is None:
        return None

    timestamp = raw.get("UtcTime", "") or raw.get("TimeCreated", "")
    if not timestamp:
        warnings.append(
            f"Sysmon EventID {event_id} missing UtcTime — skipped"
        )
        return None

    timestamp = _normalize_timestamp(timestamp, event_id, warnings)
    if timestamp is None:
        return None

    user = raw.get("User", "")
    if "\\" in user:
        user = user.split("\\", 1)[1]

    # ── Event-type-specific field extraction ──────────────────────────

    dst_host = ""
    dst_port = 0
    src_ip = ""
    object_name = None
    process_name = None
    process_id = None
    success = True  # Sysmon records only log what happened, not failures

    if event_id == 3:  # NetworkConnect
        dst_host = (
            raw.get("DestinationHostname")
            or raw.get("DestinationIp", "")
        )
        dst_port = _coerce_int(raw.get("DestinationPort")) or 0
        src_ip = raw.get("SourceIp", "")
        process_name = raw.get("Image", "")
        process_id = _coerce_int(raw.get("ProcessId"))

    elif event_id == 11:  # FileCreate
        # For file_access events, dst_host is the machine generating the event.
        # MABE's file_access events target file_server nodes — the host field
        # carries the server name.
        dst_host = raw.get("host", "")
        object_name = raw.get("TargetFilename", "")
        # File server port inference from host name
        dst_port = _infer_port_from_hostname(dst_host)
        process_name = raw.get("Image", "")
        process_id = _coerce_int(raw.get("ProcessId"))

    elif event_id == 13:  # RegistryValueSet
        dst_host = raw.get("host", "")
        object_name = raw.get("TargetObject", "")
        dst_port = 0

    elif event_id == 22:  # DNSQuery
        dst_host = raw.get("QueryName", "")
        dst_port = 53
        process_name = raw.get("Image", "")
        process_id = _coerce_int(raw.get("ProcessId"))

    protocol = _port_to_protocol(dst_port)

    return {
        "timestamp":    timestamp,
        "session_id":   session_id,
        "user":         user,
        "event_type":   event_type,
        "dst_host":     dst_host,
        "dst_port":     dst_port,
        "src_ip":       src_ip,
        "protocol":     protocol,
        "success":      success,
        "object_name":  object_name,
        "process_name": process_name,
        "process_id":   process_id,
        "_event_id":    event_id,
        "_source":      "sysmon",
    }


# ---------------------------------------------------------------------------
# Port / protocol inference helpers
# ---------------------------------------------------------------------------

def _infer_port_from_auth_package(
    auth_pkg: str,
    dst_host: str,
    warnings: list[str],
) -> int:
    """
    Infer dst_port from AuthenticationPackageName, with hostname fallback.

    Resolution order:
    1. Direct lookup in AUTH_PACKAGE_TO_PORT
    2. Hostname prefix heuristic (HOSTNAME_PREFIX_TO_PORT)
    3. Default to 0 (unknown — NodeClassifier returns "unknown")
    """
    if auth_pkg:
        port = AUTH_PACKAGE_TO_PORT.get(auth_pkg)
        if port is not None:
            return port

    # Hostname heuristic
    if dst_host:
        port = _infer_port_from_hostname(dst_host)
        if port != 0:
            return port

    # No inference possible — NodeClassifier will return "unknown"
    return 0


def _infer_port_from_hostname(hostname: str) -> int:
    """
    Infer port from hostname prefix heuristics.

    e.g. "DC-01" → 88, "DB-02" → 1433, "FS-01" → 445
    """
    if not hostname:
        return 0
    prefix = hostname.lower()
    for pattern, port in HOSTNAME_PREFIX_TO_PORT:
        if prefix.startswith(pattern):
            return port
    return 0


def _auth_package_to_protocol(auth_pkg: str) -> str:
    """
    Map AuthenticationPackageName to a protocol string.

    The core mechanisms don't use the protocol field directly for
    detection, but it's preserved for evidence display in reports.
    """
    mapping = {
        "Kerberos":   "kerberos",
        "NTLM":       "ntlm",
        "Negotiate":  "ntlm",    # Negotiate usually resolves to Kerberos or NTLM
        "MSSQL":      "mssql",
        "PostgreSQL": "postgresql",
    }
    return mapping.get(auth_pkg, auth_pkg.lower() if auth_pkg else "unknown")


def _port_to_protocol(port: int) -> str:
    """Reverse-map a port number to a protocol string for display."""
    mapping = {
        88:   "kerberos",
        389:  "ldap",
        636:  "ldaps",
        445:  "smb",
        1433: "mssql",
        5432: "postgresql",
        3306: "mysql",
        5000: "docker_registry",
        2049: "nfs",
        514:  "syslog",
        9200: "elasticsearch",
        5601: "kibana",
        80:   "http",
        443:  "https",
        8443: "https",
        3389: "rdp",
        53:   "dns",
    }
    return mapping.get(port, "unknown")


# ---------------------------------------------------------------------------
# Timestamp normalization
# ---------------------------------------------------------------------------

# Patterns accepted as input timestamps from MABE event files.
# MABE's formatter produces ISO 8601 with Z suffix, but defensive
# handling of minor variations keeps the ingester robust.
_TS_PATTERNS = [
    # Canonical MABE format: 2025-11-14T09:00:02.312Z
    (re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"), "canonical"),
    # No milliseconds: 2025-11-14T09:00:02Z → pad to .000Z
    (re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"), "no_ms"),
    # Space separator: 2025-11-14 09:00:02.312 → convert to T + Z
    (re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+$"), "space_sep"),
    # Space separator, no ms: 2025-11-14 09:00:02
    (re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"), "space_no_ms"),
]


def _normalize_timestamp(
    ts: str,
    event_id: int,
    warnings: list[str],
) -> str | None:
    """
    Ensure timestamp is ISO 8601 with millisecond precision and Z suffix.

    Returns None if the timestamp cannot be normalized.
    """
    if not ts:
        return None

    ts = ts.strip()

    # Already canonical
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", ts):
        return ts

    # No milliseconds: append .000
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ts):
        return ts[:-1] + ".000Z"

    # Space separator with fractional seconds
    m = re.match(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\.(\d+)$", ts)
    if m:
        ms = m.group(3)[:3].ljust(3, "0")
        return f"{m.group(1)}T{m.group(2)}.{ms}Z"

    # Space separator without fractional seconds
    m = re.match(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})$", ts)
    if m:
        return f"{m.group(1)}T{m.group(2)}.000Z"

    warnings.append(
        f"EventID {event_id}: unrecognized timestamp format '{ts}' — skipped"
    )
    return None


# ---------------------------------------------------------------------------
# Manifest / session_id / account helpers
# ---------------------------------------------------------------------------

_SESSION_UUID_RE = re.compile(
    r"session_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)


def _extract_session_id(dir_name: str, warnings: list[str]) -> str:
    """
    Extract UUID from a directory name like "session_{uuid}".

    Falls back to the full directory name if pattern doesn't match.
    """
    m = _SESSION_UUID_RE.match(dir_name)
    if m:
        return m.group(1)

    warnings.append(
        f"Directory name '{dir_name}' does not match 'session_{{uuid}}' — "
        "using full name as session_id"
    )
    return dir_name


def _extract_account_from_manifest(
    manifest_path: Path,
    warnings: list[str],
) -> str:
    """
    Read session_manifest.json and return the account field.

    Only reads 'user' and 'session_id'. Does NOT read 'is_attack' —
    this enforces ground-truth blindness in the detector.
    """
    if not manifest_path.exists():
        warnings.append(
            f"session_manifest.json not found at {manifest_path} — "
            "account will be inferred from events"
        )
        return ""

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as exc:
        warnings.append(f"Failed to read manifest {manifest_path}: {exc}")
        return ""

    # Explicit allowlist: only read non-label fields.
    # This makes the ground-truth isolation policy visible in the code.
    account = manifest.get("user", "")
    # Note: manifest["is_attack"] is deliberately NOT accessed here.
    return account


def _infer_account_from_events(events: list[dict]) -> str:
    """
    Infer the primary account from normalized events.

    Returns the most frequently occurring non-empty user field.
    """
    user_counts: dict[str, int] = {}
    for e in events:
        u = e.get("user", "")
        if u:
            user_counts[u] = user_counts.get(u, 0) + 1

    if not user_counts:
        return ""
    return max(user_counts, key=lambda u: user_counts[u])


# ---------------------------------------------------------------------------
# JSON loading helper
# ---------------------------------------------------------------------------

def _load_json_list(
    path: Path,
    label: str,
    warnings: list[str],
) -> list[dict]:
    """
    Load a JSON file expected to contain a list of dicts.

    Tolerates:
    - Empty list (returns [])
    - JSON array at top level
    - JSON object (wraps in list)
    - JSON Lines format (one JSON object per line)
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except OSError as exc:
        warnings.append(f"Failed to read {label} ({path}): {exc}")
        return []

    if not raw:
        return []

    # Try standard JSON parse first
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            return [data]
        warnings.append(
            f"{label}: unexpected JSON type {type(data).__name__} — skipped"
        )
        return []
    except json.JSONDecodeError:
        pass

    # Fall back to JSON Lines
    records: list[dict] = []
    for i, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError as exc:
            warnings.append(
                f"{label} line {i}: JSON parse error ({exc}) — skipped"
            )
    return records


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def _coerce_int(value: object) -> int | None:
    """Coerce a value to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _snip(d: dict, max_len: int = 80) -> str:
    """Return a short string representation of a dict for warning messages."""
    s = str(d)
    return s[:max_len] + "..." if len(s) > max_len else s
