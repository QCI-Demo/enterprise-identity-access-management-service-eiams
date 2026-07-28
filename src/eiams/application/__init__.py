"""Application layer containing services and ports.

The application layer orchestrates domain logic and defines the
ports (interfaces) for infrastructure adapters. It depends on
domain contracts but not on infrastructure implementations.
"""

from .ports import (
    InputPort,
    OutputPort,
)

__all__ = [
    "InputPort",
    "OutputPort",
]
