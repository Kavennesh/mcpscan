"""The bundled rule pack.

A package rather than a bare directory so ``importlib.resources`` can find the
YAML after a pip install, where ``__file__``-relative paths do not survive.

The rules themselves are the ``.yaml`` files beside this one. There is no Python
here and there should not be: a bundled rule travels the same loader path as a
contributed one, which is what stops the YAML path rotting behind a privileged
built-in path.
"""

from __future__ import annotations
