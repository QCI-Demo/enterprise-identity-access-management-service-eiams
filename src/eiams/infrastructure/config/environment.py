"""Environment-backed configuration provider.

Reads policy and security values from process environment variables using
a namespace prefix, for example
``EIAMS_SECURITY__PASSWORD__ARGON2__TIME_COST=4``. Values are never logged.
"""

import os
from typing import Mapping

from eiams.shared.config import (
    ConfigurationProvider,
    LayeredConfigurationProvider,
    MappingConfigurationProvider,
)


DEFAULT_ENVIRONMENT_PREFIX = "EIAMS"


class EnvironmentConfigurationProvider(ConfigurationProvider):
    """Configuration provider backed by environment variables.

    A snapshot of the environment is taken at construction time so that
    configuration cannot change underneath a running request.
    """

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        prefix: str = DEFAULT_ENVIRONMENT_PREFIX,
    ) -> None:
        """Initialize the provider.

        Args:
            environ: Environment mapping. Defaults to ``os.environ``.
            prefix: Namespace prefix stripped from variable names.
        """
        source = dict(environ if environ is not None else os.environ)
        self._delegate = MappingConfigurationProvider(source, prefix=prefix)
        self._prefix = prefix

    @property
    def prefix(self) -> str:
        """The namespace prefix in use."""
        return self._prefix

    def get_raw(self, key: str) -> str | None:
        """Resolve the raw value for a key from the environment snapshot."""
        return self._delegate.get_raw(key)


def create_configuration_provider(
    overrides: Mapping[str, str] | None = None,
    defaults: Mapping[str, str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    prefix: str = DEFAULT_ENVIRONMENT_PREFIX,
) -> ConfigurationProvider:
    """Create the layered provider used by the composition root.

    Precedence: explicit overrides, then the environment, then packaged
    defaults.
    """
    layers: list[ConfigurationProvider] = []
    if overrides:
        layers.append(MappingConfigurationProvider(overrides))
    layers.append(EnvironmentConfigurationProvider(environ, prefix=prefix))
    if defaults:
        layers.append(MappingConfigurationProvider(defaults))
    return LayeredConfigurationProvider(layers)
