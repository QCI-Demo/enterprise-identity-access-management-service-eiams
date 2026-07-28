"""Tests for structured logging with correlation awareness."""

import json
import pytest

from eiams.shared.kernel import ActorId, TenantId, CorrelationId
from eiams.shared.context import RequestContextFactory
from eiams.shared.logging import (
    LogLevel,
    LogEvent,
    LogEventBuilder,
    LogOutcome,
    StructuredLogger,
    SecretRedactor,
)
from eiams.shared.logging.structured_logging import (
    CaptureLogOutput,
    ConsoleLogOutput,
)


class TestLogEvent:
    """Tests for LogEvent."""

    def test_log_event_to_dict(self):
        """LogEvent should serialize to dictionary."""
        event = LogEvent(
            level=LogLevel.INFO,
            message="Test message",
            correlation_id="corr-123",
            actor_id="actor-456",
            tenant_id="tenant-789",
            outcome=LogOutcome.SUCCESS,
            operation="test_op",
        )

        result = event.to_dict()

        assert result["level"] == "info"
        assert result["message"] == "Test message"
        assert result["correlation_id"] == "corr-123"
        assert result["actor_id"] == "actor-456"
        assert result["tenant_id"] == "tenant-789"
        assert result["outcome"] == "success"
        assert result["operation"] == "test_op"
        assert "timestamp" in result

    def test_log_event_to_json(self):
        """LogEvent should serialize to JSON string."""
        event = LogEvent(
            level=LogLevel.ERROR,
            message="Error occurred",
        )

        json_str = event.to_json()
        parsed = json.loads(json_str)

        assert parsed["level"] == "error"
        assert parsed["message"] == "Error occurred"

    def test_log_event_omits_none_fields(self):
        """LogEvent should omit fields that are None."""
        event = LogEvent(
            level=LogLevel.INFO,
            message="Simple message",
        )

        result = event.to_dict()

        assert "correlation_id" not in result
        assert "actor_id" not in result
        assert "tenant_id" not in result
        assert "outcome" not in result


class TestLogEventBuilder:
    """Tests for LogEventBuilder."""

    def test_builder_with_context(self):
        """Builder should extract metadata from request context."""
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
            correlation_id=str(CorrelationId.generate()),
        )

        event = (
            LogEventBuilder()
            .with_context(context)
            .info()
            .message("Test")
            .build()
        )

        assert event.correlation_id == str(context.correlation_id)
        assert event.actor_id == str(context.actor_id)
        assert event.tenant_id == str(context.tenant_id)

    def test_builder_fluent_interface(self):
        """Builder should support fluent method chaining."""
        event = (
            LogEventBuilder()
            .level(LogLevel.WARNING)
            .message("Warning message")
            .correlation_id("corr-123")
            .actor_id("actor-456")
            .tenant_id("tenant-789")
            .outcome(LogOutcome.FAILURE)
            .operation("save_user")
            .resource("user", "user-001")
            .duration_ms(150.5)
            .build()
        )

        assert event.level == LogLevel.WARNING
        assert event.message == "Warning message"
        assert event.correlation_id == "corr-123"
        assert event.actor_id == "actor-456"
        assert event.tenant_id == "tenant-789"
        assert event.outcome == LogOutcome.FAILURE
        assert event.operation == "save_user"
        assert event.resource_type == "user"
        assert event.resource_id == "user-001"
        assert event.duration_ms == 150.5

    def test_builder_shorthand_levels(self):
        """Builder should support shorthand level methods."""
        assert LogEventBuilder().debug().build().level == LogLevel.DEBUG
        assert LogEventBuilder().info().build().level == LogLevel.INFO
        assert LogEventBuilder().warning().build().level == LogLevel.WARNING
        assert LogEventBuilder().error().build().level == LogLevel.ERROR
        assert LogEventBuilder().critical().build().level == LogLevel.CRITICAL

    def test_builder_shorthand_outcomes(self):
        """Builder should support shorthand outcome methods."""
        assert LogEventBuilder().success().build().outcome == LogOutcome.SUCCESS
        assert LogEventBuilder().failure().build().outcome == LogOutcome.FAILURE
        assert LogEventBuilder().denied().build().outcome == LogOutcome.DENIED

    def test_builder_redacts_extra_data(self):
        """Builder should redact sensitive data in extra fields."""
        event = (
            LogEventBuilder()
            .message("Auth attempt")
            .extra(username="john", password="secret123")
            .build()
        )

        assert event.extra["username"] == "john"
        assert event.extra["password"] == "[REDACTED]"

    def test_builder_redacts_exception(self):
        """Builder should redact sensitive data in exceptions."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        exc = ValueError(f"Invalid token: {jwt}")

        event = (
            LogEventBuilder()
            .error()
            .message("Token validation failed")
            .exception(exc)
            .build()
        )

        assert jwt not in event.extra["exception"]["message"]
        assert "[REDACTED]" in event.extra["exception"]["message"]


class TestCaptureLogOutput:
    """Tests for CaptureLogOutput."""

    def test_captures_events(self):
        """CaptureLogOutput should capture all written events."""
        output = CaptureLogOutput()

        output.write(LogEvent(level=LogLevel.INFO, message="First"))
        output.write(LogEvent(level=LogLevel.ERROR, message="Second"))

        assert len(output.events) == 2
        assert output.events[0].message == "First"
        assert output.events[1].message == "Second"

    def test_clear_events(self):
        """CaptureLogOutput.clear() should remove all events."""
        output = CaptureLogOutput()
        output.write(LogEvent(level=LogLevel.INFO, message="Test"))

        output.clear()

        assert len(output.events) == 0

    def test_find_by_operation(self):
        """CaptureLogOutput should find events by operation."""
        output = CaptureLogOutput()
        output.write(LogEvent(level=LogLevel.INFO, message="A", operation="op1"))
        output.write(LogEvent(level=LogLevel.INFO, message="B", operation="op2"))
        output.write(LogEvent(level=LogLevel.INFO, message="C", operation="op1"))

        results = output.find_by_operation("op1")

        assert len(results) == 2
        assert results[0].message == "A"
        assert results[1].message == "C"

    def test_find_by_correlation_id(self):
        """CaptureLogOutput should find events by correlation ID."""
        output = CaptureLogOutput()
        output.write(LogEvent(level=LogLevel.INFO, message="A", correlation_id="c1"))
        output.write(LogEvent(level=LogLevel.INFO, message="B", correlation_id="c2"))

        results = output.find_by_correlation_id("c1")

        assert len(results) == 1
        assert results[0].message == "A"


class TestStructuredLogger:
    """Tests for StructuredLogger."""

    def test_logger_creates_event_builder(self):
        """Logger should create event builders."""
        logger = StructuredLogger()

        builder = logger.event()

        assert isinstance(builder, LogEventBuilder)

    def test_logger_logs_events(self):
        """Logger should write events to output."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)

        event = logger.event().info().message("Test").build()
        logger.log(event)

        assert len(output.events) == 1
        assert output.events[0].message == "Test"

    def test_log_operation_convenience_method(self):
        """log_operation should create complete events."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            correlation_id="test-corr-id",
        )

        logger.log_operation(
            context=context,
            operation="user_create",
            outcome=LogOutcome.SUCCESS,
            message="User created",
            resource_type="user",
            resource_id="user-123",
            duration_ms=45.2,
        )

        assert len(output.events) == 1
        event = output.events[0]
        assert event.operation == "user_create"
        assert event.outcome == LogOutcome.SUCCESS
        assert event.correlation_id == "test-corr-id"
        assert event.resource_type == "user"
        assert event.resource_id == "user-123"
        assert event.duration_ms == 45.2

    def test_log_error_convenience_method(self):
        """log_error should create error events."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
        )
        exc = ValueError("Something went wrong")

        logger.log_error(
            context=context,
            message="Operation failed",
            exception=exc,
            operation="test_op",
        )

        assert len(output.events) == 1
        event = output.events[0]
        assert event.level == LogLevel.ERROR
        assert event.outcome == LogOutcome.ERROR
        assert "exception" in event.extra


class TestLoggerSecretRedaction:
    """Integration tests for secret redaction in logging."""

    def test_secrets_never_appear_in_output(self):
        """Verify secrets are never present in log output."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)

        secrets = {
            "password": "supersecret123",
            "api_key": "sk-1234567890abcdef",
            "refresh_token": "rt-token-value",
            "client_secret": "my-client-secret",
        }

        # Log with secrets in extra data
        event = (
            logger.event()
            .info()
            .message("Auth attempt")
            .extra(**secrets)
            .build()
        )
        logger.log(event)

        # Convert to JSON (as would be done for actual output)
        json_output = output.events[0].to_json()

        # Verify no secrets appear
        for secret_value in secrets.values():
            assert secret_value not in json_output

    def test_jwt_redacted_from_message(self):
        """JWTs in messages should be redacted."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

        event = (
            logger.event()
            .info()
            .message("Processing request")
            .extra(token=jwt)
            .build()
        )
        logger.log(event)

        json_output = output.events[0].to_json()

        assert jwt not in json_output

    def test_correlation_metadata_preserved(self):
        """Correlation metadata should not be redacted."""
        output = CaptureLogOutput()
        logger = StructuredLogger(output=output)
        context = RequestContextFactory.create(
            actor_id=str(ActorId.generate()),
            tenant_id=str(TenantId.generate()),
        )

        logger.log_operation(
            context=context,
            operation="test",
            outcome=LogOutcome.SUCCESS,
            message="Test",
        )

        event = output.events[0]
        assert event.correlation_id is not None
        assert event.actor_id is not None
        assert event.tenant_id is not None
