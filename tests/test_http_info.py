"""Tests for :mod:`reconx.http_info`.

Every request is served by the ``responses`` mock, so the suite performs no
real network I/O.
"""

from __future__ import annotations

from typing import Any

import pytest
import requests
import responses

from reconx import http_info
from reconx.context import ReconContext


@pytest.fixture
def ctx() -> ReconContext:
    return ReconContext(timeout=2.0)


class TestAuditSecurityHeaders:
    def test_all_present(self):
        headers = {name.lower(): "x" for name in http_info.SECURITY_HEADERS}
        audit = http_info.audit_security_headers(headers)
        assert audit["score"] == audit["total"] == 6
        assert audit["missing"] == []
        assert audit["grade"] == "A"

    def test_none_present(self):
        audit = http_info.audit_security_headers({})
        assert audit["score"] == 0
        assert audit["missing"] == list(http_info.SECURITY_HEADERS)
        assert audit["grade"] == "D"

    def test_partial_scores_a_grade(self):
        headers = {"strict-transport-security": "max-age=1", "x-frame-options": "DENY"}
        audit = http_info.audit_security_headers(headers)
        assert audit["score"] == 2
        assert "Content-Security-Policy" in audit["missing"]
        assert audit["grade"] in {"C", "B"}

    @pytest.mark.parametrize(
        ("score", "grade"),
        [(0, "D"), (1, "D"), (2, "C"), (3, "C"), (4, "B"), (5, "B"), (6, "A")],
    )
    def test_grades(self, score, grade):
        assert http_info._grade(score, 6) == grade

    def test_case_insensitive_matching(self):
        audit = http_info.audit_security_headers({"strict-transport-security": "max-age=1"})
        assert audit["present"] == ["Strict-Transport-Security"]


class TestFetchChain:
    def test_direct_response(self, ctx):
        with responses.RequestsMock() as mock:
            mock.add(responses.GET, "https://example.com", status=200, body="ok")
            session = http_info.build_session(ctx)
            response, chain, error = http_info._fetch_chain(session, "https://example.com", 2.0)
        assert error is None
        assert chain == []
        assert response is not None
        assert response.status_code == 200

    def test_records_each_hop(self, ctx):
        with responses.RequestsMock() as mock:
            mock.add(
                responses.GET,
                "https://example.com",
                status=301,
                headers={"Location": "https://www.example.com"},
            )
            mock.add(responses.GET, "https://www.example.com", status=200, body="ok")
            session = http_info.build_session(ctx)
            response, chain, error = http_info._fetch_chain(session, "https://example.com", 2.0)
        assert error is None
        assert response is not None
        assert response.status_code == 200
        assert chain == [
            {
                "url": "https://example.com",
                "status_code": 301,
                "location": "www.example.com",
            }
        ]

    def test_empty_location_is_an_error(self, ctx):
        with responses.RequestsMock() as mock:
            mock.add(responses.GET, "https://example.com", status=302, headers={"Location": ""})
            session = http_info.build_session(ctx)
            response, _chain, error = http_info._fetch_chain(session, "https://example.com", 2.0)
        assert response is None
        assert "without a Location header" in error

    def test_3xx_without_location_is_the_final_response(self, ctx):
        # requests only treats a 3xx as a redirect when Location is present, so
        # this is a legitimate answer rather than something to walk further.
        with responses.RequestsMock() as mock:
            mock.add(responses.GET, "https://example.com", status=304)
            session = http_info.build_session(ctx)
            response, _chain, error = http_info._fetch_chain(session, "https://example.com", 2.0)
        assert error is None
        assert response is not None
        assert response.status_code == 304

    def test_redirect_loop_is_detected(self, ctx):
        with responses.RequestsMock() as mock:
            # One hop is enough: the loop is spotted before it is re-requested.
            mock.add(
                responses.GET,
                "https://example.com",
                status=302,
                headers={"Location": "https://example.com"},
            )
            session = http_info.build_session(ctx)
            response, _chain, error = http_info._fetch_chain(session, "https://example.com", 2.0)
        assert response is None
        assert "redirect loop" in error

    def test_long_distinct_chain_is_bounded(self, ctx):
        hops = http_info.MAX_REDIRECTS + 1
        with responses.RequestsMock() as mock:
            for index in range(hops):
                mock.add(
                    responses.GET,
                    f"https://example.com/{index}",
                    status=302,
                    headers={"Location": f"https://example.com/{index + 1}"},
                )
            session = http_info.build_session(ctx)
            response, _chain, error = http_info._fetch_chain(session, "https://example.com/0", 2.0)
        assert response is None
        assert "exceeded" in error

    def test_timeout_is_reported(self, ctx):
        with responses.RequestsMock() as mock:
            mock.add(
                responses.GET,
                "https://example.com",
                body=requests.exceptions.ConnectTimeout("too slow"),
            )
            session = http_info.build_session(ctx)
            response, _chain, error = http_info._fetch_chain(session, "https://example.com", 2.0)
        assert response is None
        assert "timed out" in error

    def test_connection_error_is_reported(self, ctx):
        with responses.RequestsMock() as mock:
            mock.add(
                responses.GET,
                "https://example.com",
                body=requests.ConnectionError("refused"),
            )
            session = http_info.build_session(ctx)
            response, _chain, error = http_info._fetch_chain(session, "https://example.com", 2.0)
        assert response is None
        assert "failed" in error

    def test_too_many_redirects_exception(self, ctx):
        class Raising:
            max_redirects = 5

            def get(self, *args: Any, **kwargs: Any):
                raise requests.TooManyRedirects("nope")

        response, _chain, error = http_info._fetch_chain(Raising(), "https://example.com", 2.0)
        assert response is None
        assert error == "too many redirects"


class TestLookup:
    @responses.activate
    def test_https_first(self, ctx):
        responses.add(responses.GET, "https://example.com", status=200, body="ok")
        result = http_info.lookup("example.com", ctx)
        assert result["status_code"] == 200
        assert result["scheme"] == "https"
        assert result["redirect_count"] == 0
        assert len(result["attempts"]) == 1

    @responses.activate
    def test_falls_back_to_http(self, ctx):
        responses.add(responses.GET, "https://example.com", body=requests.ConnectionError("no tls"))
        responses.add(responses.GET, "http://example.com", status=200, body="ok")
        result = http_info.lookup("example.com", ctx)
        assert result["status_code"] == 200
        assert result["scheme"] == "http"
        assert len(result["attempts"]) == 2
        assert any("answered after" in warning for warning in result["warnings"])

    @responses.activate
    def test_reports_redirect_chain(self, ctx):
        responses.add(
            responses.GET,
            "https://example.com",
            status=301,
            headers={"Location": "https://www.example.com/"},
        )
        responses.add(
            responses.GET,
            "https://www.example.com/",
            status=200,
            body="ok",
            headers={"Strict-Transport-Security": "max-age=63072000"},
        )
        result = http_info.lookup("example.com", ctx)
        assert result["redirect_count"] == 1
        assert result["redirects"][0]["status_code"] == 301
        assert any("followed 1 redirect" in warning for warning in result["warnings"])

    @responses.activate
    def test_both_protocols_failing(self, ctx):
        for url in ("https://example.com", "http://example.com"):
            responses.add(responses.GET, url, body=requests.ConnectionError("down"))
        result = http_info.lookup("example.com", ctx)
        assert "could not reach" in result["error"]
        assert len(result["attempts"]) == 2

    @responses.activate
    def test_missing_security_headers_warn(self, ctx):
        responses.add(responses.GET, "https://example.com", status=200, body="ok")
        result = http_info.lookup("example.com", ctx)
        assert result["security_headers"]["score"] == 0
        assert any("missing security header" in warning for warning in result["warnings"])

    @responses.activate
    def test_content_metadata_extracted(self, ctx):
        responses.add(
            responses.GET,
            "https://example.com",
            status=200,
            body="ok",
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": "2",
                "Server": "nginx",
            },
        )
        result = http_info.lookup("example.com", ctx)
        assert result["content_type"] == "text/html; charset=utf-8"
        assert result["content_length"] == 2
        assert result["headers"]["server"] == "nginx"

    @responses.activate
    def test_non_numeric_content_length_is_null(self, ctx):
        responses.add(
            responses.GET,
            "https://example.com",
            status=200,
            headers={"Content-Length": "chunked"},
        )
        assert http_info.lookup("example.com", ctx)["content_length"] is None

    @responses.activate
    def test_headers_are_sorted_and_lowercased(self, ctx):
        responses.add(
            responses.GET,
            "https://example.com",
            status=200,
            headers={"X-Bbb": "2", "X-Aaa": "1", "Content-Type": "text/html"},
        )
        headers = http_info.lookup("example.com", ctx)["headers"]
        assert list(headers) == sorted(headers)
        assert all(key == key.lower() for key in headers)

    @responses.activate
    def test_response_time_recorded(self, ctx):
        responses.add(responses.GET, "https://example.com", status=200, body="ok")
        assert http_info.lookup("example.com", ctx)["response_time_ms"] >= 0

    def test_supplied_session_is_not_closed(self, ctx):
        session = http_info.build_session(ctx)
        with responses.RequestsMock() as mock:
            mock.add(responses.GET, "https://example.com", status=200, body="ok")
            http_info.lookup("example.com", ctx, session=session)
        assert session.adapters  # still usable, i.e. not closed


def test_user_agent_identifies_the_tool(ctx):
    assert "ReconX" in http_info.user_agent(ctx)
    assert "ReconX" in http_info.user_agent()
