"""Logging configuration for OVN-NetDiag."""

from __future__ import annotations

import logging
import sys

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured: bool = False


def configure_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the root logger for the application.

    Args:
        verbose: If True, set level to DEBUG; otherwise INFO.

    Returns:
        The configured root logger.
    """
    global _configured
    root = logging.getLogger("ovn_netdiag")
    if _configured:
        root.setLevel(logging.DEBUG if verbose else logging.INFO)
        return root

    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    root.addHandler(handler)
    root.setLevel(level)
    _configured = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the application root."""
    return logging.getLogger(f"ovn_netdiag.{name}")
