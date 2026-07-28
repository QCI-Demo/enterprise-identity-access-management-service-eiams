"""Unit tests for shared kernel value objects."""

import pytest
from datetime import datetime, timezone

from eiams.shared.kernel import (
    EntityId,
    TenantId,
    ActorId,
    CorrelationId,
    Timestamp,
)
from eiams.shared.errors import (
    ValidationError,
    InvalidTenantError,
    InvalidActorError,
    InvalidCorrelationIdError,
)


class TestEntityId:
    """Tests for EntityId value object."""

    def test_create_with_valid_uuid(self):
        """EntityId should accept valid UUID strings."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        entity_id = EntityId(valid_uuid)
        assert entity_id.value == valid_uuid.lower()

    def test_create_with_uppercase_uuid(self):
        """EntityId should normalize UUIDs to lowercase."""
        uppercase_uuid = "550E8400-E29B-41D4-A716-446655440000"
        entity_id = EntityId(uppercase_uuid)
        assert entity_id.value == uppercase_uuid.lower()

    def test_create_with_whitespace(self):
        """EntityId should strip whitespace."""
        uuid_with_spaces = "  550e8400-e29b-41d4-a716-446655440000  "
        entity_id = EntityId(uuid_with_spaces)
        assert entity_id.value == "550e8400-e29b-41d4-a716-446655440000"

    def test_reject_invalid_uuid(self):
        """EntityId should reject invalid UUID formats."""
        with pytest.raises(ValidationError):
            EntityId("not-a-uuid")

    def test_reject_empty_string(self):
        """EntityId should reject empty strings."""
        with pytest.raises(ValidationError):
            EntityId("")

    def test_reject_none(self):
        """EntityId should reject None."""
        with pytest.raises(ValidationError):
            EntityId(None)  # type: ignore

    def test_generate_creates_valid_id(self):
        """EntityId.generate() should create a valid ID."""
        entity_id = EntityId.generate()
        assert entity_id.value is not None
        assert len(entity_id.value) == 36

    def test_equality(self):
        """EntityIds with same value should be equal."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        id1 = EntityId(uuid)
        id2 = EntityId(uuid)
        assert id1 == id2

    def test_inequality(self):
        """EntityIds with different values should not be equal."""
        id1 = EntityId.generate()
        id2 = EntityId.generate()
        assert id1 != id2

    def test_hashable(self):
        """EntityIds should be hashable for use in sets/dicts."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        entity_id = EntityId(uuid)
        entity_set = {entity_id}
        assert entity_id in entity_set

    def test_str_returns_value(self):
        """str() should return the ID value."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        entity_id = EntityId(uuid)
        assert str(entity_id) == uuid

    def test_to_dict(self):
        """to_dict() should return serializable dict."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        entity_id = EntityId(uuid)
        assert entity_id.to_dict() == {"id": uuid}


class TestTenantId:
    """Tests for TenantId value object."""

    def test_create_with_valid_uuid(self):
        """TenantId should accept valid UUID strings."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        tenant_id = TenantId(valid_uuid)
        assert tenant_id.value == valid_uuid.lower()

    def test_reject_invalid_uuid_with_specific_error(self):
        """TenantId should raise InvalidTenantError for invalid UUIDs."""
        with pytest.raises(InvalidTenantError) as exc_info:
            TenantId("not-a-uuid")
        assert "not-a-uuid" in str(exc_info.value.details)

    def test_reject_empty_string(self):
        """TenantId should reject empty strings."""
        with pytest.raises(InvalidTenantError):
            TenantId("")

    def test_generate_creates_valid_id(self):
        """TenantId.generate() should create a valid ID."""
        tenant_id = TenantId.generate()
        assert tenant_id.value is not None


class TestActorId:
    """Tests for ActorId value object."""

    def test_create_with_valid_uuid(self):
        """ActorId should accept valid UUID strings."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        actor_id = ActorId(valid_uuid)
        assert actor_id.value == valid_uuid.lower()

    def test_reject_invalid_uuid_with_specific_error(self):
        """ActorId should raise InvalidActorError for invalid UUIDs."""
        with pytest.raises(InvalidActorError) as exc_info:
            ActorId("not-a-uuid")
        assert "not-a-uuid" in str(exc_info.value.details)

    def test_reject_empty_string(self):
        """ActorId should reject empty strings."""
        with pytest.raises(InvalidActorError):
            ActorId("")

    def test_generate_creates_valid_id(self):
        """ActorId.generate() should create a valid ID."""
        actor_id = ActorId.generate()
        assert actor_id.value is not None


class TestCorrelationId:
    """Tests for CorrelationId value object."""

    def test_create_with_valid_uuid(self):
        """CorrelationId should accept valid UUID strings."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        correlation_id = CorrelationId(valid_uuid)
        assert correlation_id.value == valid_uuid

    def test_create_with_alphanumeric_string(self):
        """CorrelationId should accept alphanumeric strings."""
        correlation_id = CorrelationId("request-12345-abc")
        assert correlation_id.value == "request-12345-abc"

    def test_reject_empty_string(self):
        """CorrelationId should reject empty strings."""
        with pytest.raises(InvalidCorrelationIdError):
            CorrelationId("")

    def test_reject_too_long_string(self):
        """CorrelationId should reject strings over 128 characters."""
        with pytest.raises(InvalidCorrelationIdError):
            CorrelationId("a" * 129)

    def test_reject_invalid_characters(self):
        """CorrelationId should reject special characters."""
        with pytest.raises(InvalidCorrelationIdError):
            CorrelationId("invalid@id!")

    def test_generate_creates_valid_id(self):
        """CorrelationId.generate() should create a valid ID."""
        correlation_id = CorrelationId.generate()
        assert correlation_id.value is not None

    def test_equality(self):
        """CorrelationIds with same value should be equal."""
        value = "test-correlation-123"
        id1 = CorrelationId(value)
        id2 = CorrelationId(value)
        assert id1 == id2


class TestTimestamp:
    """Tests for Timestamp value object."""

    def test_create_with_datetime(self):
        """Timestamp should accept datetime objects."""
        dt = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        timestamp = Timestamp(dt)
        assert timestamp.value == dt

    def test_create_without_value_uses_now(self):
        """Timestamp should use current time if no value provided."""
        before = datetime.now(timezone.utc)
        timestamp = Timestamp()
        after = datetime.now(timezone.utc)
        assert before <= timestamp.value <= after

    def test_now_creates_current_timestamp(self):
        """Timestamp.now() should create current timestamp."""
        before = datetime.now(timezone.utc)
        timestamp = Timestamp.now()
        after = datetime.now(timezone.utc)
        assert before <= timestamp.value <= after

    def test_from_iso_parses_string(self):
        """Timestamp.from_iso() should parse ISO 8601 strings."""
        iso_string = "2024-01-15T12:00:00+00:00"
        timestamp = Timestamp.from_iso(iso_string)
        assert timestamp.value.year == 2024
        assert timestamp.value.month == 1
        assert timestamp.value.day == 15

    def test_from_iso_handles_z_suffix(self):
        """Timestamp.from_iso() should handle Z suffix."""
        iso_string = "2024-01-15T12:00:00Z"
        timestamp = Timestamp.from_iso(iso_string)
        assert timestamp.value.tzinfo == timezone.utc

    def test_from_iso_rejects_invalid_string(self):
        """Timestamp.from_iso() should reject invalid strings."""
        with pytest.raises(ValidationError):
            Timestamp.from_iso("not-a-timestamp")

    def test_to_iso_returns_string(self):
        """to_iso() should return ISO 8601 formatted string."""
        dt = datetime(2024, 1, 15, 12, 0, 0, 0, tzinfo=timezone.utc)
        timestamp = Timestamp(dt)
        iso = timestamp.to_iso()
        assert iso.endswith("Z")
        assert "2024-01-15" in iso

    def test_comparison_operators(self):
        """Timestamps should support comparison operators."""
        earlier = Timestamp(datetime(2024, 1, 1, tzinfo=timezone.utc))
        later = Timestamp(datetime(2024, 12, 31, tzinfo=timezone.utc))

        assert earlier < later
        assert earlier <= later
        assert later > earlier
        assert later >= earlier
        assert earlier == Timestamp(datetime(2024, 1, 1, tzinfo=timezone.utc))

    def test_naive_datetime_assumed_utc(self):
        """Naive datetimes should be assumed to be UTC."""
        naive_dt = datetime(2024, 1, 15, 12, 0, 0)
        timestamp = Timestamp(naive_dt)
        assert timestamp.value.tzinfo == timezone.utc
