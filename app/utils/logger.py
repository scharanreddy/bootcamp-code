from __future__ import annotations

import logging
import os
from logging import Logger


def configure_logger() -> None:
    """Configure structured logging for ThreatLens AI.

    The logger writes to console only and defaults to INFO level.
    If the environment variable DEBUG is set to a truthy value, logging uses DEBUG.
    """
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    log_level = logging.INFO
    if os.getenv("DEBUG", "false").lower() in {"1", "true", "yes", "on"}:
        log_level = logging.DEBUG

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)
    root_logger.propagate = False


def get_logger(name: str) -> Logger:
    """Return a logger configured for the given module name."""
    configure_logger()
    return logging.getLogger(name)
