"""Infrastructure configuration adapters.

Concrete configuration sources for the shared configuration abstraction.
"""

from .environment import (
    DEFAULT_ENVIRONMENT_PREFIX,
    EnvironmentConfigurationProvider,
    create_configuration_provider,
)

__all__ = [
    "DEFAULT_ENVIRONMENT_PREFIX",
    "EnvironmentConfigurationProvider",
    "create_configuration_provider",
]
