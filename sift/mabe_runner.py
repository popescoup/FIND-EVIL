"""
MABE Detector — SIFT Entry Point
==================================
Version: 1.0.0

Top-level CLI for running the MABE detection pipeline against a SIFT
output directory. Wires ingest → baseline → detect → report into a
single command.

USAGE
-----
From detector-sift/:

    # Minimal — point at MABE output, write reports to ./reports/
    python -m sift.mabe_runner --input output/sift/

    # With LLM narrative enhancement
    python -m sift.mabe_runner --input output/sift/ --llm-narrative

    # Custom output directory and threshold
    python -m sift.mabe_runner \\
        --input output/sift/ \\
        --output reports/run_001/ \\
        --threshold 0.40

    # Calibration mode: run and print score distribution, no reports written
    python -m sift.mabe_runner --input output/sift/ --calibrate

    # Single session evaluation (useful for debugging one bundle)
    python -m sift.mabe_runner \\
        --input output/sift/ \\
        --session 550e8400-e29b-41d4-a716-446655440000

    # Verbose logging
    python -m sift.mabe_runner --input output/sift/ -v

FLAGS
-----
--input   PATH      Path to MABE output/sift/ directory (required)
--output  PATH      Report output directory (default: ./reports/)
--threshold FLOAT   Alert threshold override (default: 0.35)
--llm-narrative     Enable LLM narrative enhancement (requires
                    ANTHROPIC_API_KEY environment variable)
--calibrate         Print score distribution and exit without writing
                    session reports. Run this first on a new dataset
                    before adjusting any threshold values.
--session UUID      Evaluate a single session by UUID and print its
                    report to stdout. Useful for debugging.
--no-summary        Skip writing run_summary.md (session reports still
                    written)
-v / --verbose      Enable DEBUG logging
-q / --quiet        Suppress all output except errors and the final
                    summary line

EXIT CODES
----------
0   Success — run completed (alerts may or may not have fired)
1   Input directory not found or no sessions loaded
2   Configuration error (bad threshold value, etc.)
3   Unexpected error during run

PROTOCOL SIFT INTEGRATION
--------------------------
When run via Claude Code on the SIFT workstation, this script is
invoked by the case-level CLAUDE.md instructions. Claude Code passes
the MABE output directory as --input and the reports directory as
--output. The exit code tells Claude Code whether to proceed to
report review or investigate the error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging setup — configured before any sift imports so module-level
# loggers in runner/reporter/ingest pick up the right level
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

logger = logging.getLogger("mabe_runner")

# ---------------------------------------------------------------------------
# Imports — after logging is configured
# ---------------------------------------------------------------------------

from sift.ingest import load_and_normalize, iter_normalized_sessions
from sift.runner import DetectionRunner, DetectionResult, SIFT_ALERT_THRESHOLD
from sift.reporter import ForensicReporter

RUNNER_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Parse arguments and run the detection pipeline.

    Returns an exit code (0 = success, 1-3 = error).
    """
    args = _parse_args(argv)
    _configure_logging(args.verbose, args.quiet)

    logger.info("MABE Detector SIFT v%s", RUNNER_VERSION)

    # ── Validate input directory ───────────────────────────────────────
    input_dir = Path(args.input)
    if not input_dir.exists():
        _error(f"Input directory not found: {input_dir}")
        return 1

    # ── Validate threshold ─────────────────────────────────────────────
    try:
        threshold = float(args.threshold)
        if not 0.0 < threshold < 1.0:
            raise ValueError
    except (TypeError, ValueError):
        _error(
            f"Invalid threshold '{args.threshold}'. "
            "Must be a float between 0.0 and 1.0."
        )
        return 2

    # ── Route to appropriate mode ──────────────────────────────────────
    if args.calibrate:
        return _run_calibrate(input_dir, threshold)

    if args.session:
        return _run_single_session(input_dir, args.session, threshold)

    return _run_full(
        input_dir=input_dir,
        output_dir=Path(args.output),
        threshold=threshold,
        llm_narrative=args.llm_narrative,
        no_summary=args.no_summary,
        quiet=args.quiet,
    )


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------

def _run_full(
    input_dir: Path,
    output_dir: Path,
    threshold: float,
    llm_narrative: bool,
    no_summary: bool,
    quiet: bool,
) -> int:
    """
    Full pipeline: ingest → detect → report.

    This is the primary mode used by the SIFT workstation and the
    demo video.
    """
    # ── Detect ────────────────────────────────────────────────────────
    runner = DetectionRunner(alert_threshold=threshold)

    try:
        result = runner.run(input_dir)
    except FileNotFoundError as exc:
        _error(str(exc))
        return 1
    except Exception as exc:
        _error(f"Detection run failed: {exc}")
        logger.debug("Traceback:", exc_info=True)
        return 3

    if result.sessions_evaluated == 0:
        _warn("No sessions were loaded. Check that --input points to "
              "a MABE output/sift/ directory containing session_* bundles.")
        return 1

    # ── Print run summary to terminal ─────────────────────────────────
    if not quiet:
        _print_run_summary(result)

    # ── Report ────────────────────────────────────────────────────────
    reporter = ForensicReporter(
        output_dir=output_dir,
        llm_narrative=llm_narrative,
    )

    try:
        written = reporter.render(result)
    except Exception as exc:
        _error(f"Report generation failed: {exc}")
        logger.debug("Traceback:", exc_info=True)
        return 3

    # ── Final output line ──────────────────────────────────────────────
    # Always printed regardless of --quiet, so Claude Code and scripts
    # can parse the result.
    summary_path = output_dir / "run_summary.md"
    print(
        f"DONE  sessions={result.sessions_evaluated}  "
        f"alerted={result.sessions_alerted}  "
        f"threshold={threshold}  "
        f"reports={output_dir}  "
        f"duration={result.run_duration_s:.1f}s"
    )

    if result.sessions_alerted > 0:
        print(f"\nAlerted sessions (highest confidence first):")
        for r in result.alerted_results:
            c = r.correlation
            fired_str = ", ".join(c.mechanisms_fired) or "none"
            print(
                f"  [{c.overall_confidence:.4f}] "
                f"{c.triage_card.account:20s}  "
                f"session={c.session_id[:8]}…  "
                f"fired={fired_str}"
            )

    if not no_summary:
        print(f"\nRun summary: {summary_path}")

    return 0


def _run_calibrate(input_dir: Path, threshold: float) -> int:
    """
    Calibration mode: run detection and print score distribution.

    No reports are written. Use this before adjusting threshold values.
    """
    print("CALIBRATION MODE — running detection, no reports will be written")
    print(f"Input: {input_dir}")
    print(f"Current threshold: {threshold}")
    print()

    runner = DetectionRunner(alert_threshold=threshold)

    try:
        result = runner.run(input_dir)
    except FileNotFoundError as exc:
        _error(str(exc))
        return 1
    except Exception as exc:
        _error(f"Detection run failed: {exc}")
        return 3

    if result.sessions_evaluated == 0:
        _warn("No sessions loaded.")
        return 1

    dist = result.score_distribution
    if not dist:
        _warn("No score distribution available.")
        return 1

    # ── Score distribution table ───────────────────────────────────────
    print("Score Distribution")
    print("=" * 40)
    print(f"  Sessions evaluated : {dist['count']}")
    print(f"  Alerted at {threshold:.2f}  : {dist['alerted']}")
    print()
    print(f"  Min    : {dist['min']:.4f}")
    print(f"  p25    : {dist['p25']:.4f}")
    print(f"  Median : {dist['median']:.4f}")
    print(f"  p75    : {dist['p75']:.4f}")
    print(f"  p90    : {dist['p90']:.4f}")
    print(f"  p95    : {dist['p95']:.4f}")
    print(f"  Max    : {dist['max']:.4f}")
    print()

    # ── Threshold sweep ────────────────────────────────────────────────
    # Show how many sessions would alert at various thresholds.
    # This is the primary calibration tool.
    scores = sorted(
        r.correlation.overall_confidence for r in result.results
    )
    print("Threshold Sweep (how many sessions alert at each threshold)")
    print("-" * 40)
    for t in (0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70):
        n = sum(1 for s in scores if s >= t)
        pct = n / len(scores) * 100
        bar = "█" * min(n, 40)
        marker = " ◄ current" if abs(t - threshold) < 0.001 else ""
        print(f"  {t:.2f}  {n:4d} ({pct:5.1f}%)  {bar}{marker}")
    print()

    # ── Dataset stats ──────────────────────────────────────────────────
    vel = result.dataset_stats.get("velocity", {})
    en  = result.dataset_stats.get("enumeration", {})
    print("Dataset Statistics (used for dynamic threshold derivation)")
    print("-" * 40)
    if vel:
        print(f"  Velocity mean rate  : {vel.get('mean_aggregate_rate', 0):.4f} eps")
        print(f"  Velocity std rate   : {vel.get('std_aggregate_rate', 0):.4f} eps")
    if en:
        print(f"  Enum mean dests     : {en.get('mean_destination_count', 0):.2f}")
        print(f"  Enum std dests      : {en.get('std_destination_count', 0):.2f}")
    print()

    return 0


def _run_single_session(
    input_dir: Path,
    session_uuid: str,
    threshold: float,
) -> int:
    """
    Evaluate a single session by UUID and print its report to stdout.

    Useful for debugging a specific bundle without running the full corpus.
    """
    # Find the bundle directory
    bundle_dir = input_dir / f"session_{session_uuid}"
    if not bundle_dir.exists():
        # Try partial UUID match
        candidates = [
            p for p in input_dir.iterdir()
            if p.is_dir() and session_uuid in p.name
        ]
        if len(candidates) == 1:
            bundle_dir = candidates[0]
            logger.info("Matched bundle: %s", bundle_dir.name)
        elif len(candidates) > 1:
            _error(
                f"Ambiguous UUID '{session_uuid}' matches "
                f"{len(candidates)} bundles. Provide more characters."
            )
            return 2
        else:
            _error(f"No session bundle found for UUID: {session_uuid}")
            return 1

    logger.info("Loading session: %s", bundle_dir.name)

    # Load the target session
    try:
        target = load_and_normalize(bundle_dir)
    except Exception as exc:
        _error(f"Failed to load session {bundle_dir.name}: {exc}")
        return 3

    # Load full corpus for baseline construction
    logger.info("Loading corpus for baseline construction...")
    corpus = list(iter_normalized_sessions(input_dir, skip_empty=True))

    if not corpus:
        _error("No sessions loaded from corpus. Cannot build baselines.")
        return 1

    logger.info(
        "Corpus: %d sessions loaded, evaluating %s",
        len(corpus), target.session_id[:8]
    )

    # Run single-session evaluation
    runner = DetectionRunner(alert_threshold=threshold)
    try:
        result = runner.run_single(target, corpus)
    except Exception as exc:
        _error(f"Evaluation failed: {exc}")
        logger.debug("Traceback:", exc_info=True)
        return 3

    # Render to stdout
    reporter = ForensicReporter(llm_narrative=False)
    report = reporter.render_single(result)
    print(report)

    return 0


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

def _print_run_summary(result: DetectionResult) -> None:
    """Print a concise run summary to the terminal."""
    print()
    print("=" * 60)
    print("  MABE DETECTOR — RUN COMPLETE")
    print("=" * 60)
    print(f"  Sessions evaluated : {result.sessions_evaluated}")
    print(f"  Sessions alerted   : {result.sessions_alerted}")
    print(f"  Alert threshold    : {result.alert_threshold}")
    print(f"  Duration           : {result.run_duration_s:.1f}s")

    if result.skipped_sessions:
        print(f"  Skipped (errors)   : {len(result.skipped_sessions)}")

    dist = result.score_distribution
    if dist:
        print()
        print(f"  Score range        : {dist['min']:.4f} — {dist['max']:.4f}")
        print(f"  Median score       : {dist['median']:.4f}")

    print("=" * 60)
    print()


def _error(msg: str) -> None:
    print(f"ERROR  {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"WARN   {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m sift.mabe_runner",
        description=(
            "MABE Detector — SIFT forensic detection pipeline.\n"
            "Runs velocity, enumeration, and privilege escalation detection\n"
            "against a MABE session bundle directory and produces Markdown\n"
            "forensic reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap_dedent("""
        examples:
          # Full run — detect and report
          python -m sift.mabe_runner --input output/sift/

          # Calibration — examine score distribution before tuning
          python -m sift.mabe_runner --input output/sift/ --calibrate

          # Single session debug
          python -m sift.mabe_runner --input output/sift/ \\
              --session 550e8400-e29b-41d4-a716-446655440000

          # With LLM narrative (requires ANTHROPIC_API_KEY)
          python -m sift.mabe_runner --input output/sift/ --llm-narrative
        """),
    )

    parser.add_argument(
        "--input", "-i",
        required=True,
        metavar="PATH",
        help="Path to MABE output/sift/ directory containing session_* bundles",
    )
    parser.add_argument(
        "--output", "-o",
        default="reports",
        metavar="PATH",
        help="Report output directory (default: ./reports/)",
    )
    parser.add_argument(
        "--threshold", "-t",
        default=SIFT_ALERT_THRESHOLD,
        type=float,
        metavar="FLOAT",
        help=f"Alert threshold (default: {SIFT_ALERT_THRESHOLD}). "
             "Lower = more alerts (recall). Higher = fewer (precision). "
             "Run --calibrate first to choose a value for your dataset.",
    )
    parser.add_argument(
        "--llm-narrative",
        action="store_true",
        default=False,
        help="Enable LLM-enhanced narrative in reports. "
             "Requires ANTHROPIC_API_KEY environment variable. "
             "Enable only after validating core detection output.",
    )
    parser.add_argument(
        "--calibrate",
        action="store_true",
        default=False,
        help="Print score distribution and threshold sweep, then exit "
             "without writing session reports. Run this on a new dataset "
             "before adjusting thresholds.",
    )
    parser.add_argument(
        "--session",
        metavar="UUID",
        default=None,
        help="Evaluate a single session by UUID (or UUID prefix) and "
             "print its report to stdout. Useful for debugging.",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        default=False,
        help="Skip writing run_summary.md (session reports still written)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable DEBUG logging",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress all output except errors and the final summary line",
    )

    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# textwrap_dedent — avoids importing textwrap at module level
# ---------------------------------------------------------------------------

def textwrap_dedent(text: str) -> str:
    """Minimal dedent for the epilog string."""
    import textwrap
    return textwrap.dedent(text)


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())