"""Acceptance test 19: no full API key, Authorization value, or X-ApiKeys
value anywhere in the log after any run, including a failing one.
"""

from __future__ import annotations

import logging

from nessus_drata.logging_setup import setup_logging


def test_secrets_are_redacted_to_last_4_chars(tmp_path):
    secret_nessus_access = "supersecretaccesskey12345"
    secret_nessus_secret = "supersecretsecretkey67890"
    secret_drata = "drata-api-key-abcdef999"

    setup_logging(
        tmp_path,
        log_level="INFO",
        secrets=[secret_nessus_access, secret_nessus_secret, secret_drata],
    )
    logger = logging.getLogger("nessus_drata.test")
    logger.info("Authorization: Bearer %s", secret_drata)
    logger.error("X-ApiKeys: accessKey=%s; secretKey=%s", secret_nessus_access, secret_nessus_secret)
    logger.info("plain message with no secrets")

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_text = (tmp_path / "collector.log").read_text()

    assert secret_nessus_access not in log_text
    assert secret_nessus_secret not in log_text
    assert secret_drata not in log_text

    assert "****2345" in log_text  # last 4 of secret_nessus_access
    assert "****7890" in log_text  # last 4 of secret_nessus_secret
    assert "****f999" in log_text  # last 4 of secret_drata

    logging.getLogger().handlers.clear()


def test_no_secrets_configured_leaves_messages_untouched(tmp_path):
    setup_logging(tmp_path, log_level="INFO", secrets=[])
    logger = logging.getLogger("nessus_drata.test2")
    logger.info("hello world")
    for handler in logging.getLogger().handlers:
        handler.flush()
    log_text = (tmp_path / "collector.log").read_text()
    assert "hello world" in log_text
    logging.getLogger().handlers.clear()
