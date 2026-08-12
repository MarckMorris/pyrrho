"""pyrrho: an adversarial reviewer for Terraform plans.

Named after Pyrrho of Elis, who declined to assert what he could not verify.
"""

__version__ = "0.1.0"

# Importing the analyzers package populates the registry as a side effect.
from . import analyzers as _analyzers  # noqa: F401,E402

__all__ = ["__version__"]
