"""Tests for the conversions shared by the entity mappers."""

from datetime import datetime, timezone

import pytest

from eiams.infrastructure.persistence.mappers.base import (
    from_timestamp,
    from_tuple,
    identifier,
    optional_identifier,
    require_timestamp,
    slugify,
    to_timestamp,
    to_tuple,
)
from eiams.shared.kernel import TenantId, Timestamp


class TestListEncoding:
    """Scopes and redirect URIs are stored as comma-separated text."""

    @pytest.mark.parametrize(
        "stored,expected",
        [
            ("user:read,user:write", ("user:read", "user:write")),
            (" user:read , user:write ", ("user:read", "user:write")),
            ("user:read", ("user:read",)),
            ("", ()),
            (None, ()),
        ],
    )
    def test_decoding(self, stored, expected):
        assert to_tuple(stored) == expected

    @pytest.mark.parametrize(
        "values,expected",
        [
            (("openid", "profile"), "openid,profile"),
            (["openid"], "openid"),
            ((), ""),
            (None, ""),
            (("openid", "  ", "profile"), "openid,profile"),
        ],
    )
    def test_encoding(self, values, expected):
        assert from_tuple(values) == expected

    def test_encoding_and_decoding_round_trip(self):
        scopes = ("user:read", "role:list")

        assert to_tuple(from_tuple(scopes)) == scopes


class TestTimestampConversion:
    """Stored datetimes become UTC timestamp value objects."""

    def test_absent_values_stay_absent(self):
        assert to_timestamp(None) is None
        assert from_timestamp(None) is None

    def test_stored_datetimes_are_read_as_utc(self):
        stored = datetime(2026, 1, 2, 3, 4, 5)

        converted = require_timestamp(stored)

        assert converted.value.tzinfo == timezone.utc

    def test_timestamps_are_written_back_unchanged(self):
        timestamp = Timestamp(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))

        assert from_timestamp(timestamp) == timestamp.value


class TestSlugDerivation:
    """Slugs are derived when a caller does not supply one."""

    @pytest.mark.parametrize(
        "name,expected",
        [
            ("Platform Engineering", "platform-engineering"),
            ("  Spaced  Out  ", "spaced-out"),
            ("Acme & Co.", "acme-co"),
            ("MiXeD CaSe", "mixed-case"),
        ],
    )
    def test_derivation(self, name, expected):
        assert slugify(name, fallback="fallback") == expected

    def test_a_name_with_nothing_usable_falls_back(self):
        assert slugify("---", fallback="fallback-value") == "fallback-value"

    def test_long_names_are_truncated_to_the_column_width(self):
        slug = slugify("word " * 40, fallback="fallback")

        assert len(slug) <= 63
        assert not slug.endswith("-")


class TestIdentifierRendering:
    """Identifiers are stored in their canonical string form."""

    def test_value_objects_render_as_their_value(self):
        tenant_id = TenantId("11111111-2222-3333-4444-555555555555")

        assert identifier(tenant_id) == "11111111-2222-3333-4444-555555555555"

    def test_absence_is_preserved(self):
        assert optional_identifier(None) is None

    def test_present_values_are_rendered(self):
        tenant_id = TenantId("11111111-2222-3333-4444-555555555555")

        assert optional_identifier(tenant_id) == str(tenant_id)
