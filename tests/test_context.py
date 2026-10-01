"""Tests for :mod:`reconx.context`."""

from __future__ import annotations

from pathlib import Path

from reconx import context


def test_defaults():
    ctx = context.default_context()
    assert ctx.timeout == 10.0
    assert ctx.concurrency == 8
    assert ctx.wordlist is None
    assert "ReconX" in ctx.user_agent


def test_is_frozen():
    ctx = context.ReconContext()
    try:
        ctx.timeout = 1.0
    except Exception as exc:
        assert "frozen" in str(exc).lower() or isinstance(exc, AttributeError)
    else:
        raise AssertionError("ReconContext should be immutable")


def test_equality_ignores_extras():
    a = context.ReconContext(timeout=5.0, extras={"one": 1})
    b = context.ReconContext(timeout=5.0, extras={"two": 2})
    assert a == b


def test_wordlist_accepts_a_path():
    assert context.ReconContext(wordlist=Path("words.txt")).wordlist == Path("words.txt")


def test_max_concurrency_is_a_sane_ceiling():
    assert context.MAX_CONCURRENCY == 32
