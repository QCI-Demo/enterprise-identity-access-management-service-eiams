"""Correlation-aware structured logging primitives.

Provides event builders and loggers that emit safe structured events
with correlation, actor, tenant, and outcome metadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol, TYPE_CHECKING

from eiams.shared.logging.redaction import SecretRedactor, RedactionConfig

if TYPE_CHECKING:
    from eiams.shared.context import RequestContext


class LogLevel(str, Enum):
    """Log severity levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogOutcome(str, Enum):
    """Standardized operation outcomes for structured logging."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class LogEvent:
    """Immutable structured log event.

    All fields are designed for safe serialization and correlation tracking.
    """

    level: LogLevel
    message: str
    correlation_id: str | None = None
    actor_id: str | None = None
    tenant_id: str | None = None
    outcome: LogOutcome | None = None
    operation: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    duration_ms: float | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {
            "level": self.level.value,
            "message": self.message,
            "timestamp": self.timestamp,
        }

        if self.correlation_id:
            result["correlation_id"] = self.correlation_id
        if self.actor_id:
            result["actor_id"] = self.actor_id
        if self.tenant_id:
            result["tenant_id"] = self.tenant_id
        if self.outcome:
            result["outcome"] = self.outcome.value
        if self.operation:
            result["operation"] = self.operation
        if self.resource_type:
            result["resource_type"] = self.resource_type
        if self.resource_id:
            result["resource_id"] = self.resource_id
        if self.duration_ms is not None:
            result["duration_ms"] = self.duration_ms
        if self.extra:
            result["extra"] = self.extra

        return result

    def to_json(self) -> str:
        """Convert to JSON string for output."""
        return json.dumps(self.to_dict())


class LogEventBuilder:
    """Builder for constructing structured log events.

    Supports fluent interface for building events with context metadata.
    """

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        """Initialize the builder.

        Args:
            redactor: Secret redactor for sanitizing event data.
        """
        self._redactor = redactor or SecretRedactor()
        self._level: LogLevel = LogLevel.INFO
        self._message: str = ""
        self._correlation_id: str | None = None
        self._actor_id: str | None = None
        self._tenant_id: str | None = None
        self._outcome: LogOutcome | None = None
        self._operation: str | None = None
        self._resource_type: str | None = None
        self._resource_id: str | None = None
        self._duration_ms: float | None = None
        self._extra: dict[str, Any] = {}

    def with_context(self, context: RequestContext) -> LogEventBuilder:
        """Set correlation, actor, and tenant from request context.

        Args:
            context: The request context to extract metadata from.

        Returns:
            Self for fluent chaining.
        """
        self._correlation_id = str(context.correlation_id)
        self._actor_id = str(context.actor_id)
        if context.tenant:
            self._tenant_id = str(context.tenant.tenant_id)
        return self

    def level(self, level: LogLevel) -> LogEventBuilder:
        """Set the log level."""
        self._level = level
        return self

    def debug(self) -> LogEventBuilder:
        """Set level to DEBUG."""
        self._level = LogLevel.DEBUG
        return self

    def info(self) -> LogEventBuilder:
        """Set level to INFO."""
        self._level = LogLevel.INFO
        return self

    def warning(self) -> LogEventBuilder:
        """Set level to WARNING."""
        self._level = LogLevel.WARNING
        return self

    def error(self) -> LogEventBuilder:
        """Set level to ERROR."""
        self._level = LogLevel.ERROR
        return self

    def critical(self) -> LogEventBuilder:
        """Set level to CRITICAL."""
        self._level = LogLevel.CRITICAL
        return self

    def message(self, msg: str) -> LogEventBuilder:
        """Set the log message."""
        self._message = msg
        return self

    def correlation_id(self, cid: str) -> LogEventBuilder:
        """Set correlation ID directly."""
        self._correlation_id = cid
        return self

    def actor_id(self, aid: str) -> LogEventBuilder:
        """Set actor ID directly."""
        self._actor_id = aid
        return self

    def tenant_id(self, tid: str) -> LogEventBuilder:
        """Set tenant ID directly."""
        self._tenant_id = tid
        return self

    def outcome(self, outcome: LogOutcome) -> LogEventBuilder:
        """Set the operation outcome."""
        self._outcome = outcome
        return self

    def success(self) -> LogEventBuilder:
        """Set outcome to SUCCESS."""
        self._outcome = LogOutcome.SUCCESS
        return self

    def failure(self) -> LogEventBuilder:
        """Set outcome to FAILURE."""
        self._outcome = LogOutcome.FAILURE
        return self

    def denied(self) -> LogEventBuilder:
        """Set outcome to DENIED."""
        self._outcome = LogOutcome.DENIED
        return self

    def operation(self, op: str) -> LogEventBuilder:
        """Set the operation name."""
        self._operation = op
        return self

    def resource(self, resource_type: str, resource_id: str | None = None) -> LogEventBuilder:
        """Set the resource being operated on."""
        self._resource_type = resource_type
        self._resource_id = resource_id
        return self

    def duration_ms(self, ms: float) -> LogEventBuilder:
        """Set the operation duration in milliseconds."""
        self._duration_ms = ms
        return self

    def extra(self, **kwargs: Any) -> LogEventBuilder:
        """Add additional structured data (will be redacted)."""
        self._extra.update(kwargs)
        return self

    def exception(self, exc: Exception) -> LogEventBuilder:
        """Add exception details (will be redacted)."""
        redacted_exc = self._redactor.redact(exc)
        self._extra["exception"] = redacted_exc
        return self

    def build(self) -> LogEvent:
        """Build the immutable LogEvent.

        Returns:
            Constructed LogEvent with all sensitive data redacted.
        """
        # Redact extra data
        redacted_extra = self._redactor.redact_for_logging(self._extra)

        return LogEvent(
            level=self._level,
            message=self._message,
            correlation_id=self._correlation_id,
            actor_id=self._actor_id,
            tenant_id=self._tenant_id,
            outcome=self._outcome,
            operation=self._operation,
            resource_type=self._resource_type,
            resource_id=self._resource_id,
            duration_ms=self._duration_ms,
            extra=redacted_extra,
        )


class LogOutput(Protocol):
    """Protocol for log output destinations."""

    def write(self, event: LogEvent) -> None:
        """Write a log event to the destination."""
        ...


class ConsoleLogOutput:
    """Writes log events to console as JSON."""

    def __init__(self, stream: Callable[[str], None] | None = None) -> None:
        """Initialize with optional output stream.

        Args:
            stream: Output function. Defaults to print.
        """
        self._stream = stream or print

    def write(self, event: LogEvent) -> None:
        """Write event as JSON line to console."""
        self._stream(event.to_json())


class CaptureLogOutput:
    """Captures log events for testing purposes."""

    def __init__(self) -> None:
        self._events: list[LogEvent] = []

    def write(self, event: LogEvent) -> None:
        """Capture the event."""
        self._events.append(event)

    @property
    def events(self) -> list[LogEvent]:
        """All captured events."""
        return list(self._events)

    def clear(self) -> None:
        """Clear captured events."""
        self._events.clear()

    def find_by_operation(self, operation: str) -> list[LogEvent]:
        """Find events by operation name."""
        return [e for e in self._events if e.operation == operation]

    def find_by_correlation_id(self, correlation_id: str) -> list[LogEvent]:
        """Find events by correlation ID."""
        return [e for e in self._events if e.correlation_id == correlation_id]


class StructuredLogger:
    """Structured logger with automatic redaction and context propagation.

    Provides a safe interface for emitting structured log events with
    automatic secret redaction applied.
    """

    def __init__(
        self,
        output: LogOutput | None = None,
        redactor: SecretRedactor | None = None,
        name: str | None = None,
    ) -> None:
        """Initialize the logger.

        Args:
            output: Log output destination. Defaults to console.
            redactor: Secret redactor. Uses default config if not provided.
            name: Logger name for identification.
        """
        self._output = output or ConsoleLogOutput()
        self._redactor = redactor or SecretRedactor()
        self._name = name

    @property
    def name(self) -> str | None:
        """Logger name."""
        return self._name

    def event(self) -> LogEventBuilder:
        """Create a new log event builder.

        Returns:
            LogEventBuilder for fluent event construction.
        """
        return LogEventBuilder(self._redactor)

    def log(self, event: LogEvent) -> None:
        """Emit a log event.

        Args:
            event: The log event to emit.
        """
        self._output.write(event)

    def log_operation(
        self,
        context: RequestContext,
        operation: str,
        outcome: LogOutcome,
        message: str,
        level: LogLevel = LogLevel.INFO,
        resource_type: str | None = None,
        resource_id: str | None = None,
        duration_ms: float | None = None,
        **extra: Any,
    ) -> None:
        """Convenience method for logging operation results.

        Args:
            context: Request context for correlation.
            operation: Operation name.
            outcome: Operation outcome.
            message: Log message.
            level: Log level.
            resource_type: Optional resource type.
            resource_id: Optional resource ID.
            duration_ms: Optional duration.
            **extra: Additional data (will be redacted).
        """
        builder = (
            self.event()
            .with_context(context)
            .level(level)
            .message(message)
            .operation(operation)
            .outcome(outcome)
        )

        if resource_type:
            builder.resource(resource_type, resource_id)
        if duration_ms is not None:
            builder.duration_ms(duration_ms)
        if extra:
            builder.extra(**extra)

        self.log(builder.build())

    def log_error(
        self,
        context: RequestContext | None,
        message: str,
        exception: Exception | None = None,
        operation: str | None = None,
        **extra: Any,
    ) -> None:
        """Convenience method for logging errors.

        Args:
            context: Optional request context.
            message: Error message.
            exception: Optional exception (will be redacted).
            operation: Optional operation name.
            **extra: Additional data (will be redacted).
        """
        builder = self.event().error().message(message)

        if context:
            builder.with_context(context)
        if operation:
            builder.operation(operation)
        if exception:
            builder.exception(exception)
        if extra:
            builder.extra(**extra)

        builder.outcome(LogOutcome.ERROR)
        self.log(builder.build())


# Module-level logger registry
_loggers: dict[str, StructuredLogger] = {}


def get_logger(
    name: str,
    output: LogOutput | None = None,
    redactor: SecretRedactor | None = None,
) -> StructuredLogger:
    """Get or create a named logger.

    Args:
        name: Logger name.
        output: Optional log output. Only used on first creation.
        redactor: Optional redactor. Only used on first creation.

    Returns:
        StructuredLogger instance.
    """
    if name not in _loggers:
        _loggers[name] = StructuredLogger(output, redactor, name)
    return _loggers[name]
