"""Smoke test: the package imports and exposes a version."""

import agent_reviewer


def test_package_has_version() -> None:
    assert isinstance(agent_reviewer.__version__, str)
    assert agent_reviewer.__version__
