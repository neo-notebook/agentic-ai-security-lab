"""Smoke test: the package imports and exposes a version."""

import triage_agent


def test_package_has_version() -> None:
    assert isinstance(triage_agent.__version__, str)
    assert triage_agent.__version__
