"""Load and validate config.yaml and checks.yaml. No I/O beyond the two file reads."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

FIELD_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

RESERVED_FIELD_NAMES = frozenset(
    {
        "id",
        "hostname",
        "host_ip",
        "host_fqdn",
        "operating_system",
        "scan_id",
        "scan_name",
        "scan_ended_at",
        "collected_at",
        "audit_file",
        "checks_evaluated",
        "checks_passed",
        "checks_failed",
        "checks_inconclusive",
        "failed_check_fields",
        "all_required_checks_passed",
        "source_fidelity",
    }
)

MATCH_KEYS_IN_PRECEDENCE = ("check_name_exact", "check_name_prefix", "check_name_contains")

REQUIRED_ENV_VARS = ("NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY", "DRATA_API_KEY")


class ConfigError(Exception):
    """Raised for any config, manifest, or data-validation error. Maps to exit code 2."""


@dataclass(frozen=True)
class NessusConfig:
    base_url: str = "https://localhost:8834"
    verify_tls: bool = True
    ca_bundle: Optional[str] = None
    scan_id: Optional[int] = None
    scan_name_exact: Optional[str] = None
    use_latest_history: bool = True
    export_format: str = "nessus"
    export_timeout_seconds: int = 900
    connect_timeout_seconds: int = 10
    read_timeout_seconds: int = 120


@dataclass(frozen=True)
class DrataConfig:
    base_url: str = "https://public-api.drata.com"
    connection_id: int = 0
    resource_id: int = 0
    use_sessions: bool = True
    batch_size: int = 25
    max_retries: int = 5
    # Spec gap: Section 4.4 references `drata.record_id_prefix` by name
    # ("id = drata.record_id_prefix + '-' + slug(host_key)") and Section 14
    # lists its assumed default ("nessus", fixed permanently at go-live), but
    # the Section 7.1 config.yaml example never actually lists this key.
    # Filling the gap with the spec's own stated default rather than
    # inventing an unrelated one.
    record_id_prefix: str = "nessus"


@dataclass(frozen=True)
class SafetyConfig:
    min_hosts: int = 50
    max_shrink_ratio: float = 0.8
    min_manifest_coverage_pct: float = 90


@dataclass(frozen=True)
class RuntimeConfig:
    artifacts_dir: str = "artifacts"
    state_dir: str = "state"
    log_dir: str = "logs"
    keep_raw_exports_days: int = 30
    keep_payloads_days: int = 14


@dataclass(frozen=True)
class CheckEntry:
    field: str
    label: str
    match_type: str  # one of MATCH_KEYS_IN_PRECEDENCE
    match_value: str
    required: bool = False


@dataclass(frozen=True)
class Secrets:
    nessus_access_key: str
    nessus_secret_key: str
    drata_api_key: str


@dataclass(frozen=True)
class AppConfig:
    nessus: NessusConfig
    drata: DrataConfig
    safety: SafetyConfig
    runtime: RuntimeConfig
    checks: tuple[CheckEntry, ...] = field(default_factory=tuple)
    secrets: Optional[Secrets] = None


def redact(value: str) -> str:
    """Redact a secret to its last 4 characters, e.g. '****ab12'.

    A secret at or under 4 characters is masked completely rather than
    shown in full -- "redact to last 4 characters" implicitly assumes the
    secret is longer than that; real API keys always are, but this must
    never be the path that leaks a short one whole.
    """
    if not value or len(value) <= 4:
        return "****"
    return f"****{value[-4:]}"


def _load_yaml(path: Path, kind: str) -> dict:
    if not path.exists():
        raise ConfigError(f"{kind} file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{kind} file is not valid YAML: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{kind} file must contain a mapping at the top level: {path}")
    return data


def _build_nessus(raw: dict) -> NessusConfig:
    defaults = NessusConfig()
    return NessusConfig(
        base_url=raw.get("base_url", defaults.base_url),
        verify_tls=raw.get("verify_tls", defaults.verify_tls),
        ca_bundle=raw.get("ca_bundle", defaults.ca_bundle),
        scan_id=raw.get("scan_id", defaults.scan_id),
        scan_name_exact=raw.get("scan_name_exact", defaults.scan_name_exact),
        use_latest_history=raw.get("use_latest_history", defaults.use_latest_history),
        export_format=raw.get("export_format", defaults.export_format),
        export_timeout_seconds=raw.get("export_timeout_seconds", defaults.export_timeout_seconds),
        connect_timeout_seconds=raw.get("connect_timeout_seconds", defaults.connect_timeout_seconds),
        read_timeout_seconds=raw.get("read_timeout_seconds", defaults.read_timeout_seconds),
    )


def _build_drata(raw: dict) -> DrataConfig:
    defaults = DrataConfig()
    return DrataConfig(
        base_url=raw.get("base_url", defaults.base_url),
        connection_id=raw.get("connection_id", defaults.connection_id),
        resource_id=raw.get("resource_id", defaults.resource_id),
        use_sessions=raw.get("use_sessions", defaults.use_sessions),
        batch_size=raw.get("batch_size", defaults.batch_size),
        max_retries=raw.get("max_retries", defaults.max_retries),
        record_id_prefix=raw.get("record_id_prefix", defaults.record_id_prefix),
    )


def _build_safety(raw: dict) -> SafetyConfig:
    defaults = SafetyConfig()
    return SafetyConfig(
        min_hosts=raw.get("min_hosts", defaults.min_hosts),
        max_shrink_ratio=raw.get("max_shrink_ratio", defaults.max_shrink_ratio),
        min_manifest_coverage_pct=raw.get(
            "min_manifest_coverage_pct", defaults.min_manifest_coverage_pct
        ),
    )


def _build_runtime(raw: dict) -> RuntimeConfig:
    defaults = RuntimeConfig()
    return RuntimeConfig(
        artifacts_dir=raw.get("artifacts_dir", defaults.artifacts_dir),
        state_dir=raw.get("state_dir", defaults.state_dir),
        log_dir=raw.get("log_dir", defaults.log_dir),
        keep_raw_exports_days=raw.get("keep_raw_exports_days", defaults.keep_raw_exports_days),
        keep_payloads_days=raw.get("keep_payloads_days", defaults.keep_payloads_days),
    )


def validate_field_name(name: str) -> None:
    if not isinstance(name, str) or not FIELD_NAME_RE.match(name):
        raise ConfigError(
            f"invalid check field name {name!r}: must match ^[a-z][a-z0-9_]{{2,63}}$"
        )
    if name in RESERVED_FIELD_NAMES:
        raise ConfigError(f"check field name {name!r} is reserved and cannot be used")


def _parse_check_entry(raw_entry: dict, index: int) -> CheckEntry:
    if "field" not in raw_entry:
        raise ConfigError(f"checks[{index}] is missing required key 'field'")
    field_name = raw_entry["field"]
    validate_field_name(field_name)

    label = raw_entry.get("label", "")
    match = raw_entry.get("match")
    if not isinstance(match, dict) or not match:
        raise ConfigError(f"checks[{index}] ({field_name}) is missing a 'match' block")

    match_type = None
    match_value = None
    for key in MATCH_KEYS_IN_PRECEDENCE:
        if key in match:
            match_type = key
            match_value = match[key]
            break
    if match_type is None:
        raise ConfigError(
            f"checks[{index}] ({field_name}) match block has none of "
            f"{MATCH_KEYS_IN_PRECEDENCE}"
        )
    if not isinstance(match_value, str) or not match_value:
        raise ConfigError(
            f"checks[{index}] ({field_name}) match.{match_type} must be a non-empty string"
        )

    required = bool(raw_entry.get("required", False))
    return CheckEntry(
        field=field_name, label=label, match_type=match_type, match_value=match_value, required=required
    )


def load_checks_manifest(path: Path) -> tuple[CheckEntry, ...]:
    raw = _load_yaml(path, "checks manifest")
    raw_checks = raw.get("checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        raise ConfigError(f"checks manifest has no 'checks' list: {path}")

    entries: list[CheckEntry] = []
    seen_fields: dict[str, int] = {}
    for idx, raw_entry in enumerate(raw_checks):
        if not isinstance(raw_entry, dict):
            raise ConfigError(f"checks[{idx}] must be a mapping")
        entry = _parse_check_entry(raw_entry, idx)
        if entry.field in seen_fields:
            raise ConfigError(
                f"duplicate check field name {entry.field!r} "
                f"(checks[{seen_fields[entry.field]}] and checks[{idx}])"
            )
        seen_fields[entry.field] = idx
        entries.append(entry)

    return tuple(entries)


def load_manifest_audit_file(path: Path) -> Optional[str]:
    """The checks manifest's top-level `audit_file` key. Separate from
    load_checks_manifest (which returns only the CheckEntry tuple) to avoid
    changing that function's already-tested return shape.
    """
    raw = _load_yaml(path, "checks manifest")
    audit_file = raw.get("audit_file")
    return audit_file if isinstance(audit_file, str) else None


def load_secrets() -> Secrets:
    missing = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
    if missing:
        raise ConfigError(f"missing required environment variable(s): {', '.join(missing)}")
    return Secrets(
        nessus_access_key=os.environ["NESSUS_ACCESS_KEY"],
        nessus_secret_key=os.environ["NESSUS_SECRET_KEY"],
        drata_api_key=os.environ["DRATA_API_KEY"],
    )


def get_required_env(name: str) -> str:
    """Fetch a single required secret on demand, raising ConfigError naming
    just that variable. Used by the `run` command so --fixtures/--dry-run
    combinations only demand the specific secrets they actually need, never
    all three unconditionally (see load_config's require_secrets param) --
    fixture mode must work with zero credentials (spec Section 2 #4, Section
    10), which validate-config's all-three-required contract (Section 7.2)
    does not have to honor.
    """
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"missing required environment variable: {name}")
    return value


def load_config(
    config_path: Path, checks_path: Path, *, require_secrets: bool = True
) -> AppConfig:
    raw = _load_yaml(config_path, "config")
    checks = load_checks_manifest(checks_path)
    secrets = load_secrets() if require_secrets else None
    return AppConfig(
        nessus=_build_nessus(raw.get("nessus", {}) or {}),
        drata=_build_drata(raw.get("drata", {}) or {}),
        safety=_build_safety(raw.get("safety", {}) or {}),
        runtime=_build_runtime(raw.get("runtime", {}) or {}),
        checks=checks,
        secrets=secrets,
    )
