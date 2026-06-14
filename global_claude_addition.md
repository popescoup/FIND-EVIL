# GLOBAL CLAUDE.md — Additions for MABE Detector
#
# INSTRUCTIONS: Append the section below to /root/.claude/CLAUDE.md
# (or create that file if it doesn't exist).
# ================================================================

## Tool Routing — AI-Driven Attack Detection

| Task | Skill |
|------|-------|
| AI-driven attack detection (MABE Detector) | `@~/.claude/skills/ai-attack-detection/SKILL.md` |

The MABE Detector MCP server (`/opt/detector-sift/detector_mcp/server.py`)
starts on-demand via the case CLAUDE.md `mcpServers` block. Do not start
it manually — Claude Code manages its lifecycle automatically.

When working in `/cases/mabe-investigation/`, always read the case
CLAUDE.md first. It contains the full autonomous investigation workflow.
