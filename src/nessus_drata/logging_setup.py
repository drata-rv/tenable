"""Rotating file + console logging with secret redaction (spec Section 8/9.2).

Never let a full API key, an Authorization value, or an X-ApiKeys value reach
a log line. The redaction filter scrubs any configured secret value down to
its last 4 characters wherever it appears in a rendered message.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Iterable

_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 5
_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class RedactionFilter(logging.Filter):
    """Replaces every configured secret value with '****<last4>' in the
    rendered message. Applied to every handler, not just one, so nothing
    bypasses it via a differently-configured handler.
    """

    def __init__(self, secrets: Iterable[str]):
        super().__init__()
        self._secrets = tuple(s for s in secrets if s)

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._secrets:
            return True
        message = record.getMessage()
        redacted = message
        for secret in self._secrets:
            if secret in redacted:
                tail = secret[-4:] if len(secret) >= 4 else secret
                redacted = redacted.replace(secret, f"****{tail}")
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def setup_logging(log_dir: Path, log_level: str = "INFO", secrets: Iterable[str] = ()) -> None:
    """Configure the root logger with a rotating file handler (5MB, 5
    backups, UTF-8) and a console handler, both carrying the redaction
    filter. Safe to call more than once (e.g. across tests) — clears any
    handlers this function previously installed.
    """
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "collector.log"

    root = logging.getLogger()
    root.setLevel(log_level.upper())
    root.handlers.clear()

    formatter = logging.Formatter(_FORMAT)
    redaction_filter = RedactionFilter(secrets)

    file_handler = logging.handlers.RotatingFileHandler(
        str(log_path), maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redaction_filter)
    root.addHandler(file_handler)

    # Force UTF-8 on the console stream where possible — the real fix for
    # Windows' legacy console code page is PYTHONUTF8=1 / PYTHONIOENCODING=utf-8
    # set by windows/run_collector.cmd (Phase 7), but reconfiguring here is a
    # harmless extra safety net when the interpreter supports it.
    stream = sys.stdout
    if hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass

    console_handler = logging.StreamHandler(stream)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redaction_filter)
    root.addHandler(console_handler)
