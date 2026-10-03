"""Finish an engagement report and use the existing guarded cleanup flow."""

import argparse
import json
from pathlib import Path


FIELDS = {
    "version": ("target_version", "Target product version"),
    "model": ("model", "Model"),
    "permission": ("permission_setting", "Permission setting"),
    "sensor": ("sensor_outcome", "Sensor outcome"),
}
OUTCOMES = {"not-run", "prevented", "completed-detected",
            "completed-not-detected", "unknown"}
STATUSES = {"VERIFIED", "FAIL", "INCOMPLETE"}
OLD_PLACEHOLDER = "RECORD_BEFORE_TESTING"
WATCH_FIELDS = ("timestamp", "status", "offline", "verification_report",
                "run_id", "run_folder", "test_cases")


def settings_from(args):
    settings = {}
    for item in getattr(args, "settings", None) or []:
        if "=" not in item:
            raise ValueError("Use --set key=value (version, model, permission, or sensor)")
        key, value = item.split("=", 1)
        if key not in FIELDS:
            raise ValueError("Unknown --set field: {}. Use version, model, permission, or sensor".format(key))
        if key in settings:
            raise ValueError("Set {} only once".format(key))
        if not value.strip():
            raise ValueError("--set {} needs a value".format(key))
        settings[key] = value.strip()
    return settings


def read_json(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object in " + str(path))
    return value


def read_watch_results(workspace):
    path = workspace / "watch-results.jsonl"
    if path.is_symlink():
        raise ValueError("Watch results cannot be a symlink")
    if not path.exists():
        return []
    results = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid watch result on line {}: {}".format(number, exc)) from exc
        if not isinstance(result, dict) or result.get("status") not in STATUSES or any(
            name in result and result[name] is not None and not isinstance(result[name], str)
            for name in ("timestamp", "run_id", "run_folder", "verification_report",
                         "started_utc", "verified_utc")
        ) or ("offline" in result and not isinstance(result["offline"], bool)):
            raise ValueError("Invalid watch result on line {}".format(number))
        cases = result.get("test_cases", {})
        if not isinstance(cases, dict) or any(
            not isinstance(case, str) or case not in {"TC-{:02d}".format(index) for index in range(1, 6)}
            or not isinstance(outcome, str) or outcome not in OUTCOMES
            for case, outcome in cases.items()
        ):
            raise ValueError("Invalid test result on line {}".format(number))
        results.append(result)
    return results


def saved_report(path_value, workspace):
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = workspace / path
    try:
        path = path.resolve(strict=True)
        path.relative_to(workspace)
    except (OSError, ValueError):
        return None
    if not path.is_file() or path.suffix != ".json":
        return None
    try:
        report = read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if report.get("status") not in STATUSES or not isinstance(report.get("run_id"), str) or not report["run_id"]:
        return None
    if any(name in report and report[name] is not None and not isinstance(report[name], str)
           for name in ("start_utc", "verified_utc")):
        return None
    return path, report


def report_paths(workspace, results):
    seen = set()
    for result in results:
        value = result.get("verification_report")
        if value and value not in seen:
            seen.add(value)
            yield value
    evidence = workspace / "evidence"
    if evidence.is_dir():
        for path in sorted(evidence.glob("*verification*.json")):
            value = str(path)
            if value not in seen:
                seen.add(value)
                yield value


def merge_runs(report, results, saved, saved_unique):
    runs = report.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError("Engagement report has an invalid run list")
    by_key = {}
    for item in runs:
        if not isinstance(item, dict):
            raise ValueError("Engagement report has an invalid run entry")
        for key in (item.get("run_folder"), item.get("run_id")):
            if isinstance(key, str) and key:
                by_key[key] = item
    for result in results:
        keys = [key for key in (result.get("run_folder"), result.get("run_id")) if key]
        if not keys:
            continue
        item = next((by_key[key] for key in keys if key in by_key), None)
        if item is None:
            item = {}
            runs.append(item)
        item.update({name: result[name] for name in (
            "run_id", "run_folder", "status", "verification_report", "offline") if name in result})
        for key in keys:
            by_key[key] = item
        if result.get("timestamp"):
            item["watched_utc"] = result["timestamp"]
        if result.get("test_cases"):
            item["test_cases"] = result["test_cases"]
        matched = saved.get(result.get("verification_report"))
        if matched and result.get("run_id") and matched["run_id"] != result["run_id"]:
            raise ValueError("Watch result and verification report have different run IDs")
        if matched and matched["status"] != result["status"]:
            raise ValueError("Watch result and verification report have different results")
        if matched and not item.get("run_id"):
            item["run_id"] = matched["run_id"]
        started = (matched or {}).get("start_utc") or result.get("started_utc")
        verified = (matched or {}).get("verified_utc") or result.get("verified_utc") or result.get("timestamp")
        if started:
            item["start_utc"] = started
        if verified:
            item["verified_utc"] = verified
    for path_value, saved_report_value in sorted(
        saved_unique.items(), key=lambda pair: pair[1].get("verified_utc") or ""
    ):
        run_id = saved_report_value.get("run_id")
        if not run_id:
            continue
        item = by_key.get(run_id)
        if item is None:
            item = next((run for run in runs if isinstance(run, dict)
                         and run.get("run_id") == run_id), None)
        if item is None:
            item = {"run_id": run_id}
            runs.append(item)
        by_key[run_id] = item
        if not item.get("watched_utc"):
            item["verification_report"] = path_value
            item["status"] = saved_report_value["status"]
        if saved_report_value.get("start_utc"):
            item.setdefault("start_utc", saved_report_value["start_utc"])
        if saved_report_value.get("verified_utc") and not item.get("watched_utc"):
            item["verified_utc"] = saved_report_value["verified_utc"]
    report["runs"] = runs


def merge_cases(report, results):
    cases = report.get("test_cases", {})
    if not isinstance(cases, dict):
        raise ValueError("Engagement report has an invalid test result list")
    for index in range(1, 7):
        key = "TC-{:02d}".format(index)
        if key not in cases:
            cases[key] = {"outcome": "not-run", "alert_ids": [], "notes": ""}
        elif not isinstance(cases[key], dict):
            raise ValueError("Engagement report has an invalid {} result".format(key))
    for result in results:
        for key, outcome in result.get("test_cases", {}).items():
            current = cases[key].get("outcome", "not-run")
            if (cases[key].get("notes") or cases[key].get("alert_ids")) and current != "not-run":
                continue
            if outcome == "not-run" and current != "not-run":
                continue
            if outcome == "unknown" and current not in ("not-run", "unknown"):
                continue
            cases[key]["outcome"] = outcome
    report["test_cases"] = cases


def merge_watch_results(report, results):
    attempts = report.get("watch_results", [])
    if not isinstance(attempts, list) or any(not isinstance(item, dict) for item in attempts):
        raise ValueError("Engagement report has an invalid watch result list")
    recorded = {}
    for existing in attempts:
        key = json.dumps({name: existing.get(name) for name in WATCH_FIELDS}, sort_keys=True)
        recorded[key] = recorded.get(key, 0) + 1
    encountered = {}
    for result in results:
        item = {name: result.get(name) for name in WATCH_FIELDS}
        key = json.dumps(item, sort_keys=True)
        encountered[key] = encountered.get(key, 0) + 1
        if encountered[key] > recorded.get(key, 0):
            attempts.append(item)
            recorded[key] = recorded.get(key, 0) + 1
    report["watch_results"] = attempts


def done(args, ops):
    workspace_value = getattr(args, "workspace", None)
    if not workspace_value:
        raise ValueError("Pass the prepared workspace to spite done")
    workspace = Path(workspace_value).expanduser().absolute().resolve()
    report_path = workspace / "ENGAGEMENT-REPORT.json"
    if report_path.is_symlink():
        raise ValueError("Engagement report cannot be a symlink")
    report = read_json(report_path)
    settings = settings_from(args)
    for key, (field, label) in FIELDS.items():
        value = settings.get(key)
        if value is None:
            saved = report.get(field)
            if isinstance(saved, str) and saved.strip() and saved != OLD_PLACEHOLDER:
                value = saved.strip()
        if value is None:
            if getattr(args, "yes", False):
                raise ValueError("For --yes, provide --set {}=...".format(key))
            value = input(label + ": ").strip()
            if not value:
                raise ValueError("{} cannot be empty".format(label))
        report[field] = value
    if report.get("sensor_configuration") == OLD_PLACEHOLDER:
        report.pop("sensor_configuration")
    results = read_watch_results(workspace)
    saved = {}
    saved_unique = {}
    for value in report_paths(workspace, results):
        found = saved_report(value, workspace)
        if found:
            path, content = found
            saved[str(path)] = content
            saved[value] = content
            saved_unique[str(path)] = content
    report["workspace"] = str(workspace)
    preparation = workspace / "preparation.json"
    prepared = read_json(preparation) if preparation.is_file() else {}
    if isinstance(prepared.get("started_utc"), str) and prepared["started_utc"]:
        report["prepared_utc"] = prepared["started_utc"]
    merge_runs(report, results, saved, saved_unique)
    merge_cases(report, results)
    merge_watch_results(report, results)
    run_starts = [run["start_utc"] for run in report["runs"]
                  if isinstance(run, dict) and isinstance(run.get("start_utc"), str)
                  and run["start_utc"]]
    if run_starts:
        report["start_utc"] = min(run_starts)
    report["end_utc"] = ops.utc()
    ops.replace_json(report_path, report)
    print("Engagement report saved: " + str(report_path))
    return ops.cleanup(argparse.Namespace(workspace=str(workspace), yes=bool(getattr(args, "yes", False))))
