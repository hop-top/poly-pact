"""Python SDK of the PACT protocol.

The import name is ``hop_top_pact``; ``pact`` belongs to the unrelated
``pact-python`` distribution. Subpackages mirror the Go import paths of
``hop.top/pact-go``: ``core``, ``core.jws``, ``core.binding``, ``adapter``,
``adapter.adaptertest``, ``adapters.memory`` and ``runner.manifest``.
"""

from importlib.metadata import version as _version

from hop_top_pact.core import *  # noqa: F403
from hop_top_pact.core import __all__ as _core_all
from hop_top_pact.errors import PactError

__version__: str = _version("hop-top-pact")

__all__ = ["PactError", "__version__", *_core_all]
