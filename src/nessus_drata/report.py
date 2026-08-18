"""Run report writer (spec Section 8). Writes artifacts/reports/<run_id>.json
and prints a short console summary on every run, including failures.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class RunReport:
    run_id: str
    started_at: str
    finished_at: str
    parse_mode: str
    scan_id: Optional[int]
    scan_name: Optional[str]
    scan_ended_at: Optional[str]
    host_count: int
    record_count: int
    checks_in_manifest: int
    manifest_coverage_pct: float
    manifest_misses: int
    manifest_ambiguous: int
    identity_fallbacks: int
    duplicate_ids: tuple
    batches_sent: int
    records_created: int
    records_updated: int
    session_id: Optional[str]
    session_action: Optional[str]
    safety_gates: tuple  # tuple of {"name":..., "passed":..., "reason":...} dicts
    exit_code: int


def write_report(reports_dir: Path, report: RunReport) -> Path:
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{report.run_id}.json"
    path.write_text(json.dumps(asdict(report), indent=2) + "\n")
    return path


def print_console_summary(report: RunReport) -> None:
    print(f"run_id={report.run_id} exit_code={report.exit_code} parse_mode={report.parse_mode}")
    print(f"  host_count={report.host_count} record_count={report.record_count}")
    print(
        f"  manifest_coverage_pct={report.manifest_coverage_pct:.1f}% "
        f"manifest_misses={report.manifest_misses} manifest_ambiguous={report.manifest_ambiguous}"
    )
    print(
        f"  identity_fallbacks={report.identity_fallbacks} "
        f"duplicate_ids={len(report.duplicate_ids)}"
    )
    if report.session_id:
        print(
            f"  session_id={report.session_id} session_action={report.session_action} "
            f"batches_sent={report.batches_sent} "
            f"records_created={report.records_created} records_updated={report.records_updated}"
        )
    for gate in report.safety_gates:
        status = "PASS" if gate["passed"] else "FAIL"
        print(f"  gate[{gate['name']}]: {status} — {gate['reason']}")
