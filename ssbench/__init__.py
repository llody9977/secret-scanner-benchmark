"""ssbench — a reproducible benchmark for secret-scanning tools.

The package builds a synthetic corpus of planted secrets and decoys with a
known ground truth (``ssbench.generate``), assembles it into a git repository
with deterministic history (``ssbench.gitbuild``), and scores the SARIF/JSON
output of scanners against the manifest (``ssbench.score``).

Every credential the generator emits is synthetic and non-functional by
construction. See ``SECURITY.md`` for the safety model.
"""

__version__ = "0.1.0"

GENERATOR_VERSION = __version__

__all__ = ["__version__", "GENERATOR_VERSION"]
