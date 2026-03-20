# hate_crack package
import re as _re
from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    _raw_version = _pkg_version("hate_crack")
except _PackageNotFoundError:
    _raw_version = "0.0.0"

# Clean setuptools-scm version for display:
#   "2.0.post1.dev0+g05b5d6dc7.d20260214" → "2.0+g05b5d6dc7"
#   "2.0.post1.dev1+g1234abc"              → "2.0+g1234abc"
#   "2.0"                                  → "2.0"
__version__ = _re.sub(r"(\.post\d+\.dev\d+|\.d\d{8})", "", _raw_version)
__version_tuple__ = tuple(
    int(x) if x.isdigit() else x for x in __version__.split(".")
)

__all__ = ["__version__", "__version_tuple__"]
