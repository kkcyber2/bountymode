# utils/logger.py
"""
Backward compatibility wrapper for logger module.
Imports from attacks.unit.logger
"""

from attacks.unit.logger import setup_logger

__all__ = ["setup_logger"]
