"""Centralized logging setup."""

from __future__ import annotations

import logging
import sys
from typing import Optional

from pqc_sdn.settings import get_settings


def configure_logging(level: Optional[str] = None) -> None:
    """Configure root logger once per process."""
    settings = get_settings()
    log_level = (level or settings.logging.level).upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format=settings.logging.format,
        stream=sys.stdout,
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
