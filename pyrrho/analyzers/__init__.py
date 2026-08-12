"""Analyzer implementations.

Importing this package registers every analyzer, so ``pyrrho.core.REGISTRY`` is
populated by the time anything asks for it.
"""

from . import network_exposure, real_diff  # noqa: F401

__all__ = ["network_exposure", "real_diff"]
