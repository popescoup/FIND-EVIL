# MABE Architecture

```
  ┌─────────────────────────────────────┐   ┌─────────────────────────────────────┐
  │ topology_enterprise.yaml            │   │ behavioral_params.yaml              │
  │ Defines 60 nodes across 4 network   │   │ Timing, traversal, credential, and  │
  │ segments with ACL rules.            │   │ scheduling params for both agents.  │
  └────────────────────┬────────────────┘   └──────────────┬──────────────────────┘
                       └──────────────┬───────────────────-┘
                                      │
                                      ▼
              ┌────────────────────────────────────────────────┐
              │ generator/vocabulary.py                        │
              │ Calls the Anthropic API once to generate       │
              │ hostnames, usernames, and IPs. Cached to disk. │
              └─────────────────────────┬──────────────────────┘
                                        │
                                        ▼
              ┌────────────────────────────────────────────────┐
              │ generator/graph_builder.py                     │
              │ Builds a NetworkX directed graph from the      │
              │ topology config. Nodes get IPs, FQDNs, ACL    │
              │ rules become directed edges.                   │
              └─────────────────────────┬──────────────────────┘
                                        │
                                        ▼
              ┌────────────────────────────────────────────────┐
              │ generator/simulate.py                          │
              │ Orchestrates all sessions, manages RNG seeds,  │
              │ and schedules start times within the sim day.  │
              └──────────────┬─────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
  ┌───────────────────────┐     ┌───────────────────────────────┐
  │ agents/benign_user.py │     │ agents/ai_attacker/           │
  │ Simulates role-based  │     │ Runs an exhaustive BFS from a │
  │ user activity with    │     │ foothold workstation. Harvests │
  │ human-speed timing.   │     │ credentials and emits Sysmon. │
  └──────────┬────────────┘     └──────────────┬────────────────┘
             │  list[Event]       list[Event]   │
             └──────────────┬──────────────────-┘
                            │
                            ▼
              ┌────────────────────────────────────────────────┐
              │ generator/labeler.py                           │
              │ Validates session consistency, backfills       │
              │ missing TTPs, and sorts events by timestamp.   │
              └──────────────┬─────────────────────────────────┘
                             │  SimulationResult
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
  ┌───────────────────────┐     ┌───────────────────────────────┐
  │ formatters/           │     │ validation/validate.py        │
  │ Writes splunk_cim and │     │ Runs 9 checks on the output   │
  │ evtx_json output to   │     │ (velocity, fan-out, schema,   │
  │ output/.              │     │ label consistency, etc.).     │
  └──────────┬────────────┘     └───────────────────────────────┘
             │
             ▼
  ┌───────────────────────────────────────────────────────────┐
  │ output/                                                   │
  │ splunk_stream.json — all events as Splunk CIM JSON Lines. │
  │ sift/session_{uuid}/ — per-session security_events.json,  │
  │ sysmon_events.json, and session_manifest.json.            │
  └───────────────────────────────────────────────────────────┘
```
