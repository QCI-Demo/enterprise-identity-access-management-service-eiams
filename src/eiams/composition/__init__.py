"""Composition root for dependency injection and module wiring.

This module provides the wiring to instantiate and connect all
EIAMS modules without requiring future service implementations.
"""

from .container import (
    ModuleContainer,
    ModuleRegistry,
    create_container,
)
from .authentication import (
    AuthenticationComponents,
    create_authentication_components,
)

__all__ = [
    "ModuleContainer",
    "ModuleRegistry",
    "create_container",
    "AuthenticationComponents",
    "create_authentication_components",
]
