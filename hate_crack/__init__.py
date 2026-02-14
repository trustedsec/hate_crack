# hate_crack package
import re as _re

from hate_crack._version import __version__ as _raw_version
from hate_crack._version import __version_tuple__

# Clean setuptools-scm version for display:
#   "2.0.post1.dev0+g05b5d6dc7.d20260214" → "2.0+g05b5d6dc7"
#   "2.0.post1.dev1+g1234abc"              → "2.0+g1234abc"
#   "2.0"                                  → "2.0"
__version__ = _re.sub(r"(\.post\d+\.dev\d+|\.d\d{8})", "", _raw_version)

__all__ = ["__version__", "__version_tuple__"]
