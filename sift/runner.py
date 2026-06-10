"""
MABE Detector — SIFT Batch Detection Runner
=============================================
Version: 1.0.0

Orchestrates the full detection pipeline across an entire MABE dataset:

    1. Ingest    — load and normalize all session bundles
    2. Baseline  — build per-account behavioral baselines (unsupervised,
                   no labels) from the full corpus
    3. Detect    — run all three mechanisms against every session,
                   excluding each session from its own baseline
    4. Correlate — combine mechanism outputs into CorrelationOutput
    5. Collect   — return DetectionResult for the reporter

FORENSIC MODE
-------------
In forensic (SIFT) mode all detection layers run regardless of whether
lower layers fired. Layer gating is a streaming optimization — in forensic
mode we have the full session available and want maximum recall. Confidence
accumulates across layers that fire; layers that don't fire contribute 0.

This is the default behavior of the mechanisms as implemented: they
evaluate all layers and accumulate confidence. The runner does not need
to do anything special to enable forensic mode.

BASELINE EXCLUSION
------------------
Each session is excluded from its own baseline via exclude_session_id.
This is a correctness requirement: including the session under test in
its own baseline would artificially compress deviation scores, reducing
detection sensitivity for attack sessions.

ALERT THRESHOLD
---------------
The runner uses alert_threshold_override=0.35 (recall-optimized for
forensic mode). The configured default is 0.50. At 0.35, the system
errs on the side of flagging more sessions and letting the analyst
sort them out — appropriate for offline forensic analysis where
investigator time is available.

DATASET SHAPE BRIDGING
-----------------------
BaselineBuilder.build() expects sessions as list[dict] with keys:
    "session_id", "user", "events"

NormalizedSession is a dataclass. The runner converts between them
via _to_baseline_record(). This is the only shape translation in
the pipeline.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.baseline import BaselineBuilder
from core.config_loader import load_thresholds, get_layer_weights
from core.correlation.agent import CorrelationAgent
from core.mechanisms.enumeration import (
    EnumerationMechanism,
    compute_enumeration_dataset_stats,
)
from core.mechanisms.priv_escalation import PrivEscMechanism
from core.mechanisms.velocity import (
    VelocityMechanism,
    compute_velocity_dataset_stats,
)
from core.node_classifier import NodeClassifier
from core.schema import CorrelationOutput, MechanismOutput

from sift.ingest import NormalizedSession, iter_normalized_sessions

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

RUNNER_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# SIFT forensic alert threshold (recall-optimized)
# ---------------------------------------------------------------------------

SIFT_ALERT_THRESHOLD = 0.35


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SessionResult:
    """
    Detection result for a single session.

    Attributes
    ----------
    session : NormalizedSession
        The normalized session that was evaluated.
    correlation : CorrelationOutput
        Full correlation output including triage card and evidence.
    mechanism_outputs : list[MechanismOutput]
        Raw per-mechanism outputs, preserved for debugging and
        threshold calibration analysis.
    evaluation_time_ms : float
        Wall-clock time to evaluate this session (all three mechanisms
        + correlation), in milliseconds.
    """
    session:            NormalizedSession
    correlation:        CorrelationOutput
    mechanism_outputs:  list[MechanismOutput]
    evaluation_time_ms: float


@dataclass
class DetectionResult:
    """
    Aggregated results for an entire MABE dataset run.

    Attributes
    ----------
    sessions_evaluated : int
        Total sessions processed (including those that did not alert).
    sessions_alerted : int
        Sessions where overall_confidence >= alert_threshold.
    alert_threshold : float
        The threshold used for this run.
    results : list[SessionResult]
        One entry per session, sorted by overall_confidence descending.
        Reporters and accuracy scripts work from this list.
    skipped_sessions : list[str]
        session_ids that failed evaluation (bad data, mechanism error).
        Logged as warnings; never silently dropped.
    dataset_stats : dict
        Velocity and enumeration dataset-level statistics computed
        during preprocessing. Preserved for inspection and calibration.
    run_duration_s : float
        Total wall-clock time for the run, in seconds.
    run_timestamp : str
        ISO 8601 UTC timestamp of when the run started.
    runner_version : str
        Version of this module.
    """
    sessions_evaluated:  int
    sessions_alerted:    int
    alert_threshold:     float
    results:             list[SessionResult] = field(default_factory=list)
    skipped_sessions:    list[str] = field(default_factory=list)
    dataset_stats:       dict = field(default_factory=dict)
    run_duration_s:      float = 0.0
    run_timestamp:       str = ""
    runner_version:      str = RUNNER_VERSION

    @property
    def alerted_results(self) -> list[SessionResult]:
        """Convenience: only results where alert_triggered is True."""
        return [r for r in self.results if r.correlation.alert_triggered]

    @property
    def score_distribution(self) -> dict:
        """
        Summary statistics of the overall_confidence distribution.

        Useful for threshold calibration — run once against a real MABE
        dataset and examine this before adjusting any threshold values.
        """
        if not self.results:
            return {}

        scores = sorted(
            r.correlation.overall_confidence for r in self.results
        )
        n = len(scores)

        def percentile(p: float) -> float:
            idx = max(0, min(n - 1, int(p / 100 * n)))
            return round(scores[idx], 4)

        alerted = [s for s in scores if s >= self.alert_threshold]

        return {
            "count":     n,
            "min":       round(scores[0], 4),
            "p25":       percentile(25),
            "median":    percentile(50),
            "p75":       percentile(75),
            "p90":       percentile(90),
            "p95":       percentile(95),
            "max":       round(scores[-1], 4),
            "alerted":   len(alerted),
            "threshold": self.alert_threshold,
        }


# ---------------------------------------------------------------------------
# DetectionRunner
# ---------------------------------------------------------------------------

class DetectionRunner:
    """
    Batch detection runner for SIFT forensic mode.

    Instantiate once per dataset run. The runner is stateless between
    runs — create a new instance to run against a different dataset.

    Parameters
    ----------
    alert_threshold : float
        Alert threshold override. Default: SIFT_ALERT_THRESHOLD (0.35).
    thresholds_override : dict | None
        Full thresholds config override. If None, loads from
        config/thresholds.yaml. Useful for calibration experiments.
    initial_privilege : str
        Privilege level assumed at session start for all sessions.
        Default: "standard_user" (MABE assumed-breach framing).
        Override for environments where some accounts have elevated
        baseline privileges.
    """

    def __init__(
        self,
        alert_threshold: float = SIFT_ALERT_THRESHOLD,
        thresholds_override: dict | None = None,
        initial_privilege: str = "standard_user",
    ) -> None:
        self._alert_threshold = alert_threshold
        self._thresholds = thresholds_override or load_thresholds()
        self._layer_weights = get_layer_weights(self._thresholds)
        self._initial_privilege = initial_privilege
        self._classifier = NodeClassifier()

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def run(self, sift_output_dir: Path | str) -> DetectionResult:
        """
        Run full detection pipeline against a MABE SIFT output directory.

        This is the primary entry point for the CLI and for the reporter.

        Pipeline:
            1. Ingest all session bundles
            2. Build dataset-level statistics (velocity + enumeration)
            3. Build per-account baselines from full corpus (no labels)
            4. For each session:
               a. Rebuild baselines excluding this session
               b. Run all three mechanisms
               c. Correlate outputs
               d. Collect SessionResult
            5. Return DetectionResult sorted by confidence descending

        Parameters
        ----------
        sift_output_dir : Path | str
            Path to MABE's output/sift/ directory.

        Returns
        -------
        DetectionResult
        """
        run_start = time.monotonic()
        run_timestamp = _now_iso()

        logger.info(
            "DetectionRunner v%s — starting run against %s",
            RUNNER_VERSION, sift_output_dir
        )

        # ── Step 1: Ingest ────────────────────────────────────────────
        logger.info("Step 1/4: Ingesting session bundles...")
        sessions = self._ingest_all(sift_output_dir)

        if not sessions:
            logger.warning("No sessions loaded — returning empty result")
            return DetectionResult(
                sessions_evaluated=0,
                sessions_alerted=0,
                alert_threshold=self._alert_threshold,
                run_timestamp=run_timestamp,
            )

        logger.info("Loaded %d sessions", len(sessions))

        # ── Step 2: Dataset-level statistics ──────────────────────────
        logger.info("Step 2/4: Computing dataset statistics...")
        baseline_records = [_to_baseline_record(s) for s in sessions]
        dataset_stats = self._compute_dataset_stats(baseline_records)

        # ── Step 3: Full-corpus baseline (for accounts with enough
        #    history — used to check minimum_sessions threshold) ───────
        logger.info("Step 3/4: Building baselines...")
        baseline_builder = BaselineBuilder()

        # ── Step 4: Evaluate each session ────────────────────────────
        logger.info("Step 4/4: Evaluating %d sessions...", len(sessions))

        results: list[SessionResult] = []
        skipped: list[str] = []

        for i, session in enumerate(sessions, 1):
            if i % 50 == 0 or i == len(sessions):
                logger.info(
                    "  Evaluating session %d/%d (account: %s)",
                    i, len(sessions), session.account or "unknown"
                )

            try:
                result = self._evaluate_session(
                    session=session,
                    all_baseline_records=baseline_records,
                    baseline_builder=baseline_builder,
                    dataset_stats=dataset_stats,
                )
                results.append(result)
            except Exception as exc:
                logger.error(
                    "Session %s evaluation failed: %s — skipping",
                    session.session_id, exc,
                    exc_info=True,
                )
                skipped.append(session.session_id)

        # Sort by confidence descending — highest-risk sessions first
        results.sort(
            key=lambda r: r.correlation.overall_confidence,
            reverse=True,
        )

        alerted = sum(1 for r in results if r.correlation.alert_triggered)
        run_duration = time.monotonic() - run_start

        logger.info(
            "Run complete: %d evaluated, %d alerted, %d skipped, %.1fs total",
            len(results), alerted, len(skipped), run_duration,
        )

        return DetectionResult(
            sessions_evaluated=len(results),
            sessions_alerted=alerted,
            alert_threshold=self._alert_threshold,
            results=results,
            skipped_sessions=skipped,
            dataset_stats=dataset_stats,
            run_duration_s=round(run_duration, 3),
            run_timestamp=run_timestamp,
        )

    def run_single(
        self,
        session: NormalizedSession,
        all_sessions: list[NormalizedSession],
    ) -> SessionResult:
        """
        Evaluate a single pre-loaded session against a provided corpus.

        Useful for testing, interactive exploration, and re-evaluation
        with different thresholds without re-ingesting the full dataset.

        Parameters
        ----------
        session : NormalizedSession
            The session to evaluate.
        all_sessions : list[NormalizedSession]
            Full corpus (including session) for baseline construction.

        Returns
        -------
        SessionResult
        """
        baseline_records = [_to_baseline_record(s) for s in all_sessions]
        dataset_stats = self._compute_dataset_stats(baseline_records)
        baseline_builder = BaselineBuilder()

        return self._evaluate_session(
            session=session,
            all_baseline_records=baseline_records,
            baseline_builder=baseline_builder,
            dataset_stats=dataset_stats,
        )

    # ------------------------------------------------------------------
    # Internal: ingestion
    # ------------------------------------------------------------------

    def _ingest_all(
        self,
        sift_output_dir: Path | str,
    ) -> list[NormalizedSession]:
        """
        Load and normalize all session bundles from a SIFT output directory.

        Sessions with zero events are skipped (iter_normalized_sessions
        handles this with skip_empty=True by default).
        """
        sessions: list[NormalizedSession] = []
        for session in iter_normalized_sessions(
            sift_output_dir, skip_empty=True
        ):
            sessions.append(session)
        return sessions

    # ------------------------------------------------------------------
    # Internal: dataset statistics
    # ------------------------------------------------------------------

    def _compute_dataset_stats(
        self,
        baseline_records: list[dict],
    ) -> dict:
        """
        Compute velocity and enumeration dataset-level statistics.

        These are passed to VelocityMechanism and EnumerationMechanism
        as the statistical reference distribution for dynamic threshold
        derivation.

        Returns a dict with two top-level keys:
            "velocity"    — output of compute_velocity_dataset_stats
            "enumeration" — output of compute_enumeration_dataset_stats
        """
        velocity_stats = compute_velocity_dataset_stats(baseline_records)
        enumeration_stats = compute_enumeration_dataset_stats(baseline_records)

        logger.debug(
            "Dataset stats — velocity: mean_rate=%.4f eps, std=%.4f; "
            "enumeration: mean_dests=%.2f, std=%.2f",
            velocity_stats.get("mean_aggregate_rate", 0),
            velocity_stats.get("std_aggregate_rate", 0),
            enumeration_stats.get("mean_destination_count", 0),
            enumeration_stats.get("std_destination_count", 0),
        )

        return {
            "velocity":    velocity_stats,
            "enumeration": enumeration_stats,
        }

    # ------------------------------------------------------------------
    # Internal: single-session evaluation
    # ------------------------------------------------------------------

    def _evaluate_session(
        self,
        session: NormalizedSession,
        all_baseline_records: list[dict],
        baseline_builder: BaselineBuilder,
        dataset_stats: dict,
    ) -> SessionResult:
        """
        Run all three mechanisms against one session and correlate.

        Baseline is rebuilt excluding this session to prevent
        contamination of the session's own deviation scores.
        """
        t_start = time.monotonic()
        evaluated_at = _now_iso()

        # ── Rebuild baselines excluding this session ──────────────────
        baselines = baseline_builder.build(
            sessions=all_baseline_records,
            exclude_session_id=session.session_id,
        )

        events = session.events

        # ── Velocity mechanism ────────────────────────────────────────
        velocity_mechanism = VelocityMechanism(
            dataset_stats=dataset_stats["velocity"],
            thresholds=self._thresholds,
            layer_weights_override=self._layer_weights,
        )
        vel_output: Optional[MechanismOutput] = velocity_mechanism.evaluate(
            session_id=session.session_id,
            events=events,
            evaluated_at=evaluated_at,
        )

        # ── Enumeration mechanism ─────────────────────────────────────
        enumeration_mechanism = EnumerationMechanism(
            dataset_stats=dataset_stats["enumeration"],
            baselines=baselines,
            thresholds=self._thresholds,
            layer_weights_override=self._layer_weights,
            classifier=self._classifier,
        )
        enum_output: Optional[MechanismOutput] = enumeration_mechanism.evaluate(
            session_id=session.session_id,
            account=session.account,
            events=events,
            evaluated_at=evaluated_at,
        )

        # ── Privilege escalation mechanism ────────────────────────────
        priv_esc_mechanism = PrivEscMechanism(
            thresholds=self._thresholds,
            layer_weights_override=self._layer_weights,
            classifier=self._classifier,
        )
        priv_output: Optional[MechanismOutput] = priv_esc_mechanism.evaluate(
            session_id=session.session_id,
            account=session.account,
            events=events,
            evaluated_at=evaluated_at,
            initial_privilege=self._initial_privilege,
        )

        # ── Collect non-None outputs ──────────────────────────────────
        # None means the mechanism could not evaluate (e.g. < 2 events
        # for velocity). Absent outputs are handled by CorrelationAgent
        # as "mechanism absent" — distinct from fired=False.
        mechanism_outputs: list[MechanismOutput] = [
            o for o in (vel_output, enum_output, priv_output)
            if o is not None
        ]

        # ── Correlation agent ─────────────────────────────────────────
        agent = CorrelationAgent(
            thresholds=self._thresholds,
            alert_threshold_override=self._alert_threshold,
            session_ref_builder=_build_sift_session_ref(session.bundle_dir),
        )
        correlation = agent.correlate(
            session_id=session.session_id,
            account=session.account or "unknown",
            mechanism_outputs=mechanism_outputs,
        )

        eval_ms = (time.monotonic() - t_start) * 1000

        return SessionResult(
            session=session,
            correlation=correlation,
            mechanism_outputs=mechanism_outputs,
            evaluation_time_ms=round(eval_ms, 2),
        )


# ---------------------------------------------------------------------------
# Convenience function: run from a directory path
# ---------------------------------------------------------------------------

def run_detection(
    sift_output_dir: Path | str,
    alert_threshold: float = SIFT_ALERT_THRESHOLD,
    thresholds_override: dict | None = None,
) -> DetectionResult:
    """
    Module-level convenience function.

    Equivalent to DetectionRunner(...).run(sift_output_dir).

    Parameters
    ----------
    sift_output_dir : Path | str
        Path to MABE's output/sift/ directory.
    alert_threshold : float
        Alert threshold. Default: 0.35 (SIFT forensic mode).
    thresholds_override : dict | None
        Full thresholds config override for calibration experiments.

    Returns
    -------
    DetectionResult
    """
    runner = DetectionRunner(
        alert_threshold=alert_threshold,
        thresholds_override=thresholds_override,
    )
    return runner.run(sift_output_dir)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_baseline_record(session: NormalizedSession) -> dict:
    """
    Convert a NormalizedSession to the dict shape BaselineBuilder expects.

    BaselineBuilder.build() requires:
        "session_id" : str
        "user"       : str
        "events"     : list[dict]

    This is the only shape translation in the pipeline.
    """
    return {
        "session_id": session.session_id,
        "user":       session.account,
        "events":     session.events,
    }


def _build_sift_session_ref(bundle_dir: Path):
    """
    Return a session_ref_builder closure for SIFT mode.

    The session_ref in CorrelationOutput is a file path to the original
    MABE bundle directory. This lets analysts open the raw logs directly
    from the report.

    Returns a callable (session_id: str) -> str.
    """
    def _builder(session_id: str) -> str:
        return str(bundle_dir)
    return _builder


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 with millisecond precision."""
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
