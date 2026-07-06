# Project Organization

This package keeps the historical command surface intact.  Current scripts stay
at the repository root because many runbooks and wrappers call them by exact
relative path.  New organization is therefore additive: docs and read-only tools
explain the project without moving functional files.

## Current Entry

```text
run_mihomo_protocol_takeover_thin_batch.ps1
  -> run_mihomo_protocol1s_batch.ps1
     -> run_1s_protocol_restart_once.ps1
        -> protocol_runtime_probe.py
```

The current baseline config is:

```text
config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json
```

## File Families

```text
controllers/
  Browser controllers and signup orchestration.

protocol_runtime_probe.py
  Runtime hook, collector routing, W0/final handling, accelerated hold probes,
  and probe-state capture.

run_*.ps1
  Single-run and batch wrappers.  Keep these names stable.

adspower_*.py / ADSPOWER_CDP_RUNBOOK.md
  AdsPower/SunBrowser CDP discovery, observation, and handoff helpers.

mihomo_*.py / start_mihomo_isolated.ps1 / stop_mihomo_isolated.ps1
  Isolated mihomo config, alive-node probing, and proxy switching.

analyze_*.py / audit_*.py / compare_*.py / summarize_*.py / verify_*.py
  Offline analysis, evidence gates, classification, and stability checks.

decode_hs_payload.py / rewrite_hs_payload.py / project_knp_scope.py
  hsprotect payload decoding, rewriting, and proof-shape projection.

docs/
  Historical and current route notes.

tools/
  Read-only maintenance helpers added for clean package validation and config
  explanation.  They are not imported by the runtime path.
```

## Duplicate Assets

The four `crcldu_auditor_*.js` files currently have identical content.  They are
kept in place to preserve timestamp-labelled references from historical notes.
Use `tools/check_package.py` to report duplicates before making a release.

## Safe Cleanup Rule

Do not move or delete root-level scripts unless every caller is updated and a
dry-run batch still prints the same command chain.  Prefer adding wrappers,
indexes, and checks over changing the current command surface.
