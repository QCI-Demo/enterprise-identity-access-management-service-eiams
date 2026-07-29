"""Correlation-aware structured logging with secret redaction.

This module provides logging primitives that emit safe structured events
with correlation, actor, tenant, and outcome metadata. All sensitive
values are recursively redacted before output.
"""

from .redaction import (
    SecretRedactor,
    RedactionConfig,
    DEFAULT_SENSITIVE_KEYS,
    DEFAULT_SENSITIVE_PATTERNS,
)
from .structured_logging import (
    LogLevel,
    LogEvent,
    LogEventBuilder,
    LogOutcome,
    StructuredLogger,
    get_logger,
)

__all__ = [
    "SecretRedactor",
    "RedactionConfig",
    "DEFAULT_SENSITIVE_KEYS",
    "DEFAULT_SENSITIVE_PATTERNS",
    "LogLevel",
    "LogEvent",
    "LogEventBuilder",
    "LogOutcome",
    "StructuredLogger",
    "get_logger",
]
