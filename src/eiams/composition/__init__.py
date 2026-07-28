"""Composition root for dependency injection and module wiring.

This module provides the wiring to instantiate and connect all
EIAMS modules without requiring future service implementations.
"""

from .container import (
    ModuleContainer,
    ModuleRegistry,
    create_container,
)

__all__ = [
    "ModuleContainer",
    "ModuleRegistry",
    "create_container",
]
