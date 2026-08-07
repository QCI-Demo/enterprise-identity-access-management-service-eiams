"""URL-safe slug helpers for lifecycle command services."""

from __future__ import annotations

import re

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_SLUG_MAX_LENGTH = 63


def slugify(value: str, fallback: str) -> str:
    """Derive a URL-safe slug, falling back when nothing usable remains."""
    slug = _SLUG_STRIP.sub("-", value.strip().lower()).strip("-")
    slug = slug[:_SLUG_MAX_LENGTH].strip("-")
    return slug or fallback[:_SLUG_MAX_LENGTH]
