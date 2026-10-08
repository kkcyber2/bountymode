# utils/logger.py

import logging
import logging.config
import sys
from typing import Optional


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Creates and returns a named logger with console + file output.

    Args:
        name:  Logger name, typically __name__ from the calling module.
        level: Logging level string — "DEBUG", "INFO", "WARNING", "ERROR".

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Don't add handlers if they're already there (avoids duplicate log lines
    # when the same module is imported multiple times).
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.addHandler(console)

    # File handler — always writes DEBUG and above to redteam.log
    try:
        file_handler = logging.FileHandler("redteam.log", mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
    except OSError as e:
        logger.warning(f"Could not open log file: {e}. Logging to console only.")

    # Prevent log records bubbling up to the root logger and printing twice.
    logger.propagate = False

    return logger
