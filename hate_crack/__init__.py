# hate_crack package
import re as _re
from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    _raw_version = _pkg_version("hate_crack")
except _PackageNotFoundError:
    _raw_version = "0.0.0"

# Clean setuptools-scm suffixes for display:
#   "2.5.1.post1.dev0" → "2.5.1"
#   "2.5.1"            → "2.5.1"
__version__ = _re.sub(r"(\.post\d+|\.dev\d+)", "", _raw_version)
__version_tuple__ = tuple(
    int(x) if x.isdigit() else x for x in __version__.split(".")
)

__all__ = ["__version__", "__version_tuple__"]
