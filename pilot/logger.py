"""Logging and observability infrastructure for Linux Command Pilot.

Implements RedactingFormatter ensuring zero passwords, keys, or sensitive
environment variables are ever written to stdout, stderr, or logfiles.
"""

import logging
from typing import Optional

from pilot.config import get_settings
from pilot.security.redactor import redact_secrets


class RedactingFormatter(logging.Formatter):
    """Logging formatter that intercepts and sanitizes sensitive credentials before output."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return redact_secrets(formatted)


def setup_logging(
    level: Optional[str] = None,
    verbose: bool = False,
) -> logging.Logger:
    """Configure root logger with redacting formatter and appropriate log level."""
    settings = get_settings()
    log_level_str = level or ("DEBUG" if verbose else settings.log_level)
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # If handlers already configured, update their formatters
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        handler.setFormatter(RedactingFormatter(fmt=fmt, datefmt="%Y-%m-%d %H:%M:%S"))
        root_logger.addHandler(handler)
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        for h in root_logger.handlers:
            h.setFormatter(RedactingFormatter(fmt=fmt, datefmt="%Y-%m-%d %H:%M:%S"))
            h.setLevel(log_level)

    return root_logger
