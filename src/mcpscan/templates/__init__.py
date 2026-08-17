"""The HTML report template.

A package rather than a bare directory so ``importlib.resources`` can find the
template after a pip install, where ``__file__``-relative paths do not survive --
the same reason ``mcpscan.rules`` is one, and the same failure if it is forgotten:
there, an empty rule set that reports every target as clean; here, a format that
raises on every invocation.

The template beside this file is the *only* markup in the project. Nothing in
``htmlreport.py`` builds HTML, because a string marked safe in Python is a string
autoescape has stopped protecting.
"""

from __future__ import annotations
