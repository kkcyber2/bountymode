# utils/__init__.py
"""
Backward compatibility module for utils imports.
Maps to attacks/unit for compatibility with existing code.
"""

from attacks.unit.logger import setup_logger
from attacks.unit.payload_manager import PayloadManager

__all__ = [
    "setup_logger",
    "PayloadManager",
]
