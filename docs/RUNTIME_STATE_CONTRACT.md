# Runtime State Contract

This repository is a clean source package.  It intentionally does not include
local run state, browser profiles, node pools, or historical trace bodies.

## Excluded State

```text
Results/
profiles/
.mihomo-isolated/
.release/
__pycache__/
```

`PACKAGE_MANIFEST.json` and `PACKAGE_CHECKSUMS.txt` describe the clean package.
Generated runtime state should remain outside that source manifest unless a
small, redacted fixture is deliberately added for offline tests.

## Expected Generated Paths

```text
Results/network/*.jsonl
Results/protocol_runtime/*.json
Results/protocol_takeover/*.jsonl
Results/diagnostics/*
profiles/*
.mihomo-isolated/alive_*.json
.mihomo-isolated/riskblock_*.json
.mihomo-isolated/protocol1s_outcomes.jsonl
```

These files may contain account names, response bodies, continuation tokens,
collector proof fragments, profile state, and node metadata.  Treat them as
sandbox evidence and do not publish them in a clean package.

## Offline Selftest Behavior

`selftest_1s_offline.py` is allowed to skip tests that require excluded runtime
fixtures.  It should still run dry-run command checks, parser checks, audit
summary checks, watcher checks, and static protocol guard checks.

Useful commands:

```powershell
python .\selftest_1s_offline.py
python .\tools\check_package.py --compile
python .\tools\check_encoding.py
python .\tools\config_explain.py
```

## Live Readiness

`status_1s_repro.py --skip-selftest` returns exit code `1` when live state is not
ready, for example when `.mihomo-isolated/alive_*.json` is missing.  That is not
a package failure; it means the local node pool has not been prepared yet.
