#!/bin/bash
# MABE Detector SIFT — One-command setup for judges
# ==================================================
# Run from /opt/detector-sift/
# Ubuntu 22.04 x86-64 (SANS SIFT Workstation)
set -e

DETECTOR_ROOT="/opt/detector-sift"
CASE_ROOT="/cases/mabe-investigation"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  MABE Detector SIFT — Setup"
echo "════════════════════════════════════════════════════════════"
echo ""

# ── Python dependencies ───────────────────────────────────────────────
echo "[1/4] Installing Python dependencies..."
pip install -r "$DETECTOR_ROOT/requirements.txt" --quiet
# Explicitly ensure anthropic is installed — required for LLM narrative
pip install anthropic --quiet
echo "  Dependencies: OK"
echo ""

# ── SIFT tool checks ──────────────────────────────────────────────────
echo "[2/4] Checking SIFT tools..."

command -v log2timeline.py >/dev/null 2>&1 \
  && echo "  plaso (log2timeline): OK" \
  || echo "  WARN: plaso not found — run: pip3 install plaso"

command -v fls >/dev/null 2>&1 \
  && echo "  sleuthkit (fls): OK" \
  || echo "  WARN: sleuthkit not found — run: apt install sleuthkit"

[ -f /opt/volatility3-2.20.0/vol.py ] \
  && echo "  volatility3: OK" \
  || echo "  WARN: volatility3 not found at /opt/volatility3-2.20.0/vol.py"

[ -d /opt/zimmermantools/net9 ] \
  && echo "  EZ Tools (EvtxECmd): OK" \
  || echo "  WARN: EZ Tools not found at /opt/zimmermantools/net9"

command -v yara >/dev/null 2>&1 \
  && echo "  yara: OK" \
  || echo "  WARN: yara not found — run: apt install yara"

command -v claude >/dev/null 2>&1 \
  && echo "  Claude Code: OK" \
  || echo "  ERROR: Claude Code not installed — see https://claude.ai/code"

echo ""

# ── MCP server smoke test ─────────────────────────────────────────────
echo "[3/4] Verifying MCP server imports..."
python3 -c "
import sys
sys.path.insert(0, '$DETECTOR_ROOT')
from sift.runner import DetectionRunner
from sift.ingest import iter_normalized_sessions
from core.schema import CorrelationOutput
print('  MCP server dependencies: OK')
" 2>&1 || echo "  WARN: MCP server dependency check failed — review output above"
echo ""

# ── Case directory structure ──────────────────────────────────────────
echo "[4/4] Creating case directory structure..."
mkdir -p "$CASE_ROOT/analysis"
mkdir -p "$CASE_ROOT/exports"
mkdir -p "$CASE_ROOT/reports"
echo "  $CASE_ROOT/analysis  — investigation notes and tool output"
echo "  $CASE_ROOT/exports   — data exports"
echo "  $CASE_ROOT/reports   — incident reports and case summary"
echo ""

# ── Copy case CLAUDE.md ───────────────────────────────────────────────
cp "$DETECTOR_ROOT/case/CLAUDE.md" "$CASE_ROOT/CLAUDE.md"
echo "  Case CLAUDE.md: copied to $CASE_ROOT/CLAUDE.md"

# ── Install detection skill ───────────────────────────────────────────
mkdir -p /root/.claude/skills/ai-attack-detection
cp "$DETECTOR_ROOT/skills/ai-attack-detection/SKILL.md" \
   /root/.claude/skills/ai-attack-detection/SKILL.md
echo "  Detection skill: installed to /root/.claude/skills/ai-attack-detection/"
echo ""

# ── Write .env file ───────────────────────────────────────────────────
if [ -n "$ANTHROPIC_API_KEY" ]; then
  echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" > "$DETECTOR_ROOT/.env"
  echo "  API key: written to $DETECTOR_ROOT/.env"
else
  echo "  WARN: ANTHROPIC_API_KEY not set — set it before running:"
  echo "    export ANTHROPIC_API_KEY=your_key_here"
  echo "    echo \"ANTHROPIC_API_KEY=\$ANTHROPIC_API_KEY\" > $DETECTOR_ROOT/.env"
fi
echo ""

# ── Configure MCP server in Claude Code project config ───────────────
echo "  Configuring MCP server for Claude Code..."
python3 -c "
import json, os

config_path = '/root/.claude.json'

# Load existing config or create minimal one
if os.path.exists(config_path):
    with open(config_path, 'r') as f:
        config = json.load(f)
else:
    config = {}

# Ensure projects key exists
if 'projects' not in config:
    config['projects'] = {}

# Add MCP server to case project config
case_root = '$CASE_ROOT'
if case_root not in config['projects']:
    config['projects'][case_root] = {}

config['projects'][case_root]['mcpServers'] = {
    'mabe-detector': {
        'command': 'python3',
        'args': ['/opt/detector-sift/detector_mcp/server.py'],
        'env': {'PYTHONPATH': '/opt/detector-sift'}
    }
}

with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)

print('  MCP server: configured in /root/.claude.json')
" 2>&1 || echo "  WARN: MCP config failed — configure manually (see README.md)"
echo ""

# ── Verify pre-generated dataset ──────────────────────────────────────
SIFT_DIR="$DETECTOR_ROOT/mabe/output/sift"
if [ -d "$SIFT_DIR" ]; then
  SESSION_COUNT=$(find "$SIFT_DIR" -maxdepth 1 -name "session_*" -type d | wc -l)
  echo "Pre-generated dataset: $SESSION_COUNT sessions found at $SIFT_DIR"
else
  echo "WARN: Pre-generated dataset not found at $SIFT_DIR"
  echo "      Generate with: cd $DETECTOR_ROOT/mabe && python main.py \\"
  echo "        --sessions-benign 1350 --sessions-attack 75 --seed 42"
fi
echo ""

# ── Final instructions ────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════════"
echo "  Setup complete."
echo ""
echo "  Next step:"
echo "    cd $CASE_ROOT && claude"
echo "    Type 'begin' at the Claude Code prompt."
echo "════════════════════════════════════════════════════════════"
echo ""