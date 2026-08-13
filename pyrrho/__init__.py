"""pyrrho: an adversarial reviewer for Terraform plans.

Named after Pyrrho of Elis, who declined to assert what he could not verify.
"""

__version__ = "0.2.1"

# Importing the analyzers package populates the registry as a side effect.
# The name is unused on purpose; the import is the point.
from . import analyzers  # noqa: F401,E402

__all__ = ["__version__", "analyzers"]
