import json
import subprocess
import sys
from pathlib import Path

from diagnose_1s_gap import diagnose


ROOT = Path(__file__).resolve().parent
OLD_SUCCESS = ROOT / "Results" / "network" / "20260622_235827_icqygmfmlhziry.jsonl"
RECENT_CLOSE1 = ROOT / "Results" / "network" / "20260623_042934_dzddfdhoqtrlr2.jsonl"


class SkipTest(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_fixtures(*paths: Path) -> None:
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise SkipTest(
            "runtime fixture(s) are not present in this clean package: "
            + ", ".join(missing)
        )


def test_diagnose_fixtures() -> None:
    require_fixtures(OLD_SUCCESS, RECENT_CLOSE1)

    old = diagnose(OLD_SUCCESS)
    recent = diagnose(RECENT_CLOSE1)

    require(old["create_200"] is True, "old fixture should prove CreateAccount 200")
    require("PASS_CREATE_200" in old["issues"], f"old fixture issues missing PASS_CREATE_200: {old['issues']}")
    require("NOT_1S_WALL" in old["issues"], f"old fixture should remain non-1s: {old['issues']}")
    require(old["route_details"]["rich_w0_result0"] >= 1, "old fixture should expose rich W0 result0 via network collector decode")

    require(recent["create_200"] is False, "recent close-1 fixture must not be counted as success")
    require("CAPTCHA_CLOSE_MINUS1" in recent["issues"], f"recent fixture should diagnose close-1: {recent['issues']}")
    require(recent["route_details"]["rich_final_result0"] >= 1, "recent fixture should have rich final result0 after network decode")
    require(recent["route_details"]["rich_w0_result0"] >= 1, "recent fixture should have rich W0 result0 after route/network decode")


def test_dryrun_parameters() -> None:
    cmd = [
        "powershell",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        ".\\run_1s_rewrite_once.ps1",
        "-ProxyUrl",
        "http://127.0.0.1:17890",
        "-CountryLabel",
        "美国",
        "-WallMs",
        "900",
        "-SessionCachedRichFinalAndW0Success",
        "-NoTriggerFinalSuccessSignals",
        "-DryRun",
    ]
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    out = proc.stdout
    require(proc.returncode == 0, f"DryRun failed code={proc.returncode} output={out}")
    for needle in [
        "-TimeWarpWallMs 900",
        "-WaitAfterMs 130000",
        "-DeferW0WaitMs 7000",
        "-SessionCachedRichInitialW0DelayMs 2800",
        "-SessionCachedRichFinalAndW0Success",
        "-NoDeferFinalResultToW0",
    ]:
        require(needle in out, f"DryRun missing {needle!r}: {out}")


def test_batch_dryrun_parameters() -> None:
    cmd = [
        "powershell",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        ".\\run_mihomo_us_1s_batch.ps1",
        "-Filter",
        "US 006",
        "-MaxNodes",
        "1",
        "-RunsPerNode",
        "3",
        "-MinSuccesses",
        "3",
        "-StopOnRiskBlock",
        "-SkipSelfTest",
        "-DryRun",
    ]
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    out = proc.stdout
    require(proc.returncode == 0, f"batch DryRun failed code={proc.returncode} output={out}")
    for needle in [
        "runs_per_node=3",
        "min_successes=3",
        "defer_w0_wait_ms=7000",
        "exclude_filter=SG001|GB006|FR 001",
        "riskblock_ledger=.mihomo-isolated\\riskblock_nodes.json",
        "ignore_riskblock_ledger=False",
        "stop_on_riskblock=True",
        "-SessionCachedRichFinalAndW0Success",
        "-SessionCachedRichInitialW0DelayMs 2800",
        "-DeferW0WaitMs 7000",
        "verify_1s_stability.py <batch-network-logs> --min-successes 3",
        "audit_1s_goal_status.py <batch-network-logs> --min-successes 3",
        "audit_1s_live_evidence.py <batch-summary-json> --min-successes 3 --json",
        "summary JSON final_gate records verify/audit exits",
        "final_evidence records strict rerun gate",
        "GOAL_EVIDENCE_COMPLETE required for exit 0",
    ]:
        require(needle in out, f"batch DryRun missing {needle!r}: {out}")
    require("--allow-riskblock" not in out, f"batch DryRun should be strict by default: {out}")


def test_verify_gate_fixtures() -> None:
    require_fixtures(OLD_SUCCESS, RECENT_CLOSE1)

    old_proc = subprocess.run(
        [
            sys.executable,
            "verify_1s_stability.py",
            str(OLD_SUCCESS),
            "--min-successes",
            "1",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    old_out = old_proc.stdout
    require(old_proc.returncode == 3, f"old non-1s CreateAccount fixture should fail with code 3: {old_out}")
    require("raw_create_200=1" in old_out, f"old fixture should have raw CreateAccount 200: {old_out}")
    require("successes=0" in old_out, f"old fixture should not count as 1s success: {old_out}")
    require("STABLE_FAIL_NOT_1S" in old_out, f"old fixture should fail specifically as not 1s: {old_out}")

    recent_proc = subprocess.run(
        [
            sys.executable,
            "verify_1s_stability.py",
            str(RECENT_CLOSE1),
            "--min-successes",
            "1",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    recent_out = recent_proc.stdout
    require(recent_proc.returncode == 1, f"recent close-1 fixture should fail generic gate: {recent_out}")
    require("raw_create_200=0" in recent_out, f"recent fixture must not have CreateAccount 200: {recent_out}")
    require("successes=0" in recent_out, f"recent fixture must not count as success: {recent_out}")
    require("STABLE_FAIL" in recent_out, f"recent fixture should fail gate: {recent_out}")


def test_goal_audit_fixtures() -> None:
    require_fixtures(OLD_SUCCESS, RECENT_CLOSE1)

    old_proc = subprocess.run(
        [
            sys.executable,
            "audit_1s_goal_status.py",
            str(OLD_SUCCESS),
            "--min-successes",
            "1",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    old_out = old_proc.stdout
    require(old_proc.returncode == 1, f"old non-1s fixture must not complete goal: {old_out}")
    require("GOAL_NOT_COMPLETE" in old_out, f"old fixture should be goal-not-complete: {old_out}")
    require("raw_create_200=1" in old_out, f"old fixture should show raw CreateAccount 200: {old_out}")
    require("create_200_not_1s=1" in old_out, f"old fixture should flag non-1s CreateAccount: {old_out}")

    recent_proc = subprocess.run(
        [
            sys.executable,
            "audit_1s_goal_status.py",
            str(RECENT_CLOSE1),
            "--min-successes",
            "1",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    recent_out = recent_proc.stdout
    require(recent_proc.returncode == 1, f"recent close-1 fixture must not complete goal: {recent_out}")
    require("GOAL_NOT_COMPLETE" in recent_out, f"recent fixture should be goal-not-complete: {recent_out}")
    require("captcha_close_minus1=1" in recent_out, f"recent fixture should expose close-1: {recent_out}")


def test_batch_summary_audit() -> None:
    summary_dir = ROOT / "Results" / "protocol_runtime"
    summary_dir.mkdir(parents=True, exist_ok=True)
    complete_path = summary_dir / "tmp_selftest_batch_summary_complete.json"
    incomplete_path = summary_dir / "tmp_selftest_batch_summary_incomplete.json"
    false_positive_path = summary_dir / "tmp_selftest_batch_summary_false_positive.json"
    try:
        complete_path.write_text(
            json.dumps(
                {
                    "created_at": "selftest",
                    "filter": "US 006",
                    "exclude_filter": "SG001|GB006|FR 001",
                    "success_count": 3,
                    "min_successes": 3,
                    "network_logs": ["a.jsonl", "b.jsonl", "c.jsonl"],
                    "results": [{"verdict": "create_account_200"}] * 3,
                    "final_gate": {
                        "verify_exit": 0,
                        "diagnose_exit": 0,
                        "audit_exit": 0,
                        "stable_pass": True,
                        "goal_complete": True,
                    },
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        ok_proc = subprocess.run(
            [sys.executable, "audit_latest_batch_summary.py", str(complete_path)],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        require(ok_proc.returncode == 0, f"complete batch summary should pass: {ok_proc.stdout}")
        require("BATCH_GOAL_COMPLETE" in ok_proc.stdout, f"complete batch summary missing status: {ok_proc.stdout}")

        incomplete_path.write_text(
            json.dumps(
                {
                    "created_at": "selftest",
                    "success_count": 1,
                    "min_successes": 3,
                    "network_logs": ["a.jsonl"],
                    "results": [{"verdict": "create_account_200"}],
                    "final_gate": {
                        "verify_exit": 1,
                        "diagnose_exit": 0,
                        "audit_exit": 1,
                        "stable_pass": False,
                        "goal_complete": False,
                    },
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        bad_proc = subprocess.run(
            [sys.executable, "audit_latest_batch_summary.py", str(incomplete_path)],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        require(bad_proc.returncode == 1, f"incomplete batch summary should fail: {bad_proc.stdout}")
        require("BATCH_GOAL_NOT_COMPLETE" in bad_proc.stdout, f"incomplete batch summary missing status: {bad_proc.stdout}")

        false_positive_path.write_text(
            json.dumps(
                {
                    "created_at": "selftest",
                    "filter": "US 006",
                    "exclude_filter": "SG001|GB006|FR 001",
                    "success_count": 1,
                    "min_successes": 3,
                    "network_logs": ["a.jsonl"],
                    "results": [{"verdict": "create_account_200"}],
                    "final_gate": {
                        "verify_exit": 0,
                        "diagnose_exit": 0,
                        "audit_exit": 0,
                        "stable_pass": True,
                        "goal_complete": True,
                    },
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        fp_proc = subprocess.run(
            [sys.executable, "audit_latest_batch_summary.py", str(false_positive_path)],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        require(fp_proc.returncode == 1, f"summary with true final_gate but insufficient evidence must fail: {fp_proc.stdout}")
        require("BATCH_GOAL_NOT_COMPLETE" in fp_proc.stdout, f"false-positive summary missing status: {fp_proc.stdout}")
    finally:
        for p in (complete_path, incomplete_path, false_positive_path):
            try:
                p.unlink()
            except FileNotFoundError:
                pass


def test_status_and_yaml_entry_dryruns() -> None:
    status_proc = subprocess.run(
        [sys.executable, "status_1s_repro.py", "--skip-selftest"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    status_out = status_proc.stdout
    require(
        status_proc.returncode in (0, 1),
        f"status --skip-selftest should render a dashboard even when live state is absent: {status_out}",
    )
    for needle in [
        "required_scripts_ok=True",
        "recommended_yaml_stability:",
        "run_mihomo_yaml_alive_then_1s.ps1",
        "recommended_preflight:",
        "recommended_completion_audit:",
        "audit_1s_completion.py",
        "recommended_triage:",
        "triage_1s_latest.py",
        "recommended_goal_live:",
        "run_1s_goal_live.ps1",
    ]:
        require(needle in status_out, f"status output missing {needle!r}: {status_out}")

    yaml_proc = subprocess.run(
        [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\run_mihomo_yaml_alive_then_1s.ps1",
            "-Filter",
            "US 006|US 008|US 007",
            "-MaxNodes",
            "1",
            "-RunsPerNode",
            "3",
            "-MinSuccesses",
            "3",
            "-StopOnRiskBlock",
            "-DryRun",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    yaml_out = yaml_proc.stdout
    require(yaml_proc.returncode == 0, f"yaml live wrapper DryRun failed: {yaml_out}")
    for needle in [
        "would refresh alive_*.json from YAML",
        "mihomo_yaml_alive_probe.py",
        "US 006|US 008|US 007",
        "runs_per_node=3",
        "GOAL_EVIDENCE_COMPLETE required for exit 0",
    ]:
        require(needle in yaml_out, f"yaml wrapper DryRun missing {needle!r}: {yaml_out}")

    yaml_no_stop_proc = subprocess.run(
        [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\run_mihomo_yaml_alive_then_1s.ps1",
            "-Filter",
            "US 006",
            "-MaxNodes",
            "1",
            "-RunsPerNode",
            "1",
            "-MinSuccesses",
            "1",
            "-DryRun",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    yaml_no_stop_out = yaml_no_stop_proc.stdout
    require(yaml_no_stop_proc.returncode == 0, f"yaml wrapper no-stop DryRun failed: {yaml_no_stop_out}")
    require(
        "stop_on_riskblock=False" in yaml_no_stop_out,
        f"yaml wrapper must not force StopOnRiskBlock when switch is absent: {yaml_no_stop_out}",
    )

    goal_live_proc = subprocess.run(
        [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\run_1s_goal_live.ps1",
            "-Filter",
            "US 006",
            "-MaxNodes",
            "1",
            "-RunsPerNode",
            "1",
            "-MinSuccesses",
            "1",
            "-DryRun",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=45,
    )
    goal_live_out = goal_live_proc.stdout
    require(goal_live_proc.returncode == 0, f"goal live DryRun failed: {goal_live_out}")
    for needle in [
        "[goal-live] DryRun preflight",
        "[goal-live] DryRun yaml/live batch",
        "run_mihomo_yaml_alive_then_1s.ps1",
        "GOAL_EVIDENCE_COMPLETE required for exit 0",
    ]:
        require(needle in goal_live_out, f"goal live DryRun missing {needle!r}: {goal_live_out}")


def test_live_evidence_audit_requires_real_logs() -> None:
    summary_dir = ROOT / "Results" / "protocol_runtime"
    summary_dir.mkdir(parents=True, exist_ok=True)
    false_positive_path = summary_dir / "tmp_selftest_live_evidence_false_positive.json"
    try:
        false_positive_path.write_text(
            json.dumps(
                {
                    "created_at": "selftest",
                    "filter": "US 006",
                    "exclude_filter": "SG001|GB006|FR 001",
                    "success_count": 3,
                    "min_successes": 3,
                    "network_logs": [
                        "Results/network/nonexistent_selftest_a.jsonl",
                        "Results/network/nonexistent_selftest_b.jsonl",
                        "Results/network/nonexistent_selftest_c.jsonl",
                    ],
                    "results": [{"verdict": "create_account_200"}] * 3,
                    "final_gate": {
                        "verify_exit": 0,
                        "diagnose_exit": 0,
                        "audit_exit": 0,
                        "stable_pass": True,
                        "goal_complete": True,
                    },
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        proc = subprocess.run(
            [sys.executable, "audit_1s_live_evidence.py", str(false_positive_path)],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        out = proc.stdout
        require(proc.returncode == 1, f"live evidence audit must reject missing logs: {out}")
        require("GOAL_EVIDENCE_NOT_COMPLETE" in out, f"live evidence audit missing not-complete status: {out}")
        require("missing_logs=3" in out, f"live evidence audit should count missing logs: {out}")
    finally:
        try:
            false_positive_path.unlink()
        except FileNotFoundError:
            pass


def test_live_goal_watcher_timeout_mode() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "watch_1s_live_goal.py",
            "--timeout-sec",
            "0",
            "--interval-sec",
            "1",
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
    )
    out = proc.stdout
    require(proc.returncode == 1, f"watcher zero-timeout should report not complete: {out}")
    require("GOAL_EVIDENCE_NOT_COMPLETE" in out, f"watcher timeout missing not-complete status: {out}")
    require("reason=timeout" in out, f"watcher timeout missing reason: {out}")


def test_live_goal_watcher_detects_same_file_update() -> None:
    from watch_1s_live_goal import summary_signature_key

    summary_dir = ROOT / "Results" / "protocol_runtime"
    summary_dir.mkdir(parents=True, exist_ok=True)
    path = summary_dir / "tmp_selftest_watcher_same_file_update.json"
    try:
        path.write_text('{"phase": 1}', encoding="utf-8")
        first_key = summary_signature_key(path)
        # NTFS timestamp resolution is high, but keep this deterministic even
        # under fast CI/local loops.
        import time

        time.sleep(0.02)
        path.write_text('{"phase": 2, "final_gate": true}', encoding="utf-8")
        second_key = summary_signature_key(path)
        require(first_key != second_key, f"watcher key must change when same summary file is updated: {first_key}")
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def test_completion_audit_no_summary_fails_cleanly() -> None:
    # Use an impossible explicit path so the final gate cannot silently fall
    # back to a latest stale summary.
    missing = ROOT / "Results" / "protocol_runtime" / "missing_selftest_completion_summary.json"
    proc = subprocess.run(
        [sys.executable, "audit_1s_completion.py", str(missing)],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    out = proc.stdout
    require(proc.returncode == 1, f"completion audit with missing summary should fail: {out}")
    require("GOAL_COMPLETE_AUDIT_FAIL" in out, f"completion audit should expose fail status: {out}")


def test_latest_triage_no_summary_points_to_live_batch() -> None:
    missing = ROOT / "Results" / "protocol_runtime" / "missing_selftest_triage_summary.json"
    proc = subprocess.run(
        [sys.executable, "triage_1s_latest.py", str(missing)],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    out = proc.stdout
    require(proc.returncode == 1, f"triage without summary should not pass completion: {out}")
    require("TRIAGE_NOT_COMPLETE" in out, f"triage should expose incomplete status: {out}")
    require("next_action=RUN_LIVE_BATCH" in out, f"triage should point to live batch when no summary exists: {out}")


def test_protocol_contains_close_retry() -> None:
    text = (ROOT / "protocol_runtime_probe.py").read_text(encoding="utf-8", errors="replace")
    for needle in [
        "captcha close status=-1 observed;",
        "waiting for fresh retry",
        "session_cached_rich_same_qi_rich_w0",
        "session_cached_rich_w0_bootstrap_from_final_cache",
        "session_cached_rich_initial_w0_delay_ms",
    ]:
        require(needle in text, f"protocol_runtime_probe.py missing {needle!r}")


def main() -> int:
    tests = [
        test_diagnose_fixtures,
        test_dryrun_parameters,
        test_batch_dryrun_parameters,
        test_verify_gate_fixtures,
        test_goal_audit_fixtures,
        test_batch_summary_audit,
        test_status_and_yaml_entry_dryruns,
        test_live_evidence_audit_requires_real_logs,
        test_live_goal_watcher_timeout_mode,
        test_live_goal_watcher_detects_same_file_update,
        test_completion_audit_no_summary_fails_cleanly,
        test_latest_triage_no_summary_points_to_live_batch,
        test_protocol_contains_close_retry,
    ]
    results = []
    for test in tests:
        try:
            test()
            results.append({"name": test.__name__, "ok": True})
            print(f"PASS {test.__name__}")
        except SkipTest as exc:
            results.append({"name": test.__name__, "ok": True, "skip": True, "reason": str(exc)})
            print(f"SKIP {test.__name__}: {exc}")
        except Exception as exc:
            results.append({"name": test.__name__, "ok": False, "error": repr(exc)})
            print(f"FAIL {test.__name__}: {exc}")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
