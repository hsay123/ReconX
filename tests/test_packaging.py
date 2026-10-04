"""Packaging regression tests: the bundled wordlist must ship with the wheel."""

from __future__ import annotations

from reconx import subdomains


def test_default_wordlist_exists():
    assert subdomains.DEFAULT_WORDLIST.is_file()


def test_default_wordlist_loads():
    words = subdomains.load_wordlist()
    assert words
    assert "www" in words
    assert words == sorted(set(words))
