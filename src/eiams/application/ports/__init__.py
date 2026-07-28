"""Application ports defining boundaries with infrastructure.

Ports define the interfaces that infrastructure adapters implement.
This enables dependency inversion - the application layer depends
on abstractions, not concrete implementations.
"""

from .base import InputPort, OutputPort

__all__ = [
    "InputPort",
    "OutputPort",
]
