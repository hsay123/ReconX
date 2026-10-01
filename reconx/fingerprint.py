"""Lightweight technology fingerprinting.

Reads what a site already tells the world about itself: ``Server`` and
``X-Powered-By`` headers, the ``generator`` meta tag, and the file extensions of
its script and stylesheet includes. No probing, no version guessing beyond what
is literally present in the response.

Every signature carries a ``confidence`` of ``"high"`` (a header or meta tag
that names the technology outright) or ``"low"`` (a filename or path fragment
that merely suggests it). Consumers can filter on that.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .context import ReconContext, default_context

__all__ = ["SIGNATURES", "detect", "lookup"]

LOGGER = logging.getLogger(__name__)

#: How much HTML is parsed for meta tags and includes. Bounded so a large page
#: cannot turn fingerprinting into a memory hog.
MAX_HTML_BYTES = 512 * 1024

#: (needle, technology, category, confidence) matched against headers and HTML.
SIGNATURES: tuple[tuple[str, str, str, str], ...] = (
    # --- server / platform headers ---
    ("cloudflare", "Cloudflare", "CDN", "high"),
    ("cloudfront", "Amazon CloudFront", "CDN", "high"),
    ("akamai", "Akamai", "CDN", "high"),
    ("fastly", "Fastly", "CDN", "high"),
    ("incapsula", "Imperva", "CDN", "high"),
    ("sucuri", "Sucuri", "CDN", "high"),
    ("varnish", "Varnish", "Cache", "high"),
    ("litespeed", "LiteSpeed", "Web server", "high"),
    ("nginx", "nginx", "Web server", "high"),
    ("apache", "Apache", "Web server", "high"),
    ("caddy", "Caddy", "Web server", "high"),
    ("iis", "Microsoft IIS", "Web server", "high"),
    ("openresty", "OpenResty", "Web server", "high"),
    ("envoy", "Envoy", "Proxy", "high"),
    # --- language and runtime headers ---
    ("php", "PHP", "Language", "high"),
    ("x-powered-by: asp.net", "ASP.NET", "Framework", "high"),
    ("express", "Express", "Framework", "high"),
    ("w3.org", "Standards-compliant HTML", "Markup", "low"),
    ("cloudflare-nginx", "nginx behind Cloudflare", "Web server", "low"),
    # --- CMS and generator meta ---
    ("wordpress", "WordPress", "CMS", "high"),
    ("drupal", "Drupal", "CMS", "high"),
    ("joomla", "Joomla", "CMS", "high"),
    ("wix.com", "Wix", "Hosting", "high"),
    ("squarespace", "Squarespace", "Hosting", "high"),
    ("shopify", "Shopify", "E-commerce", "high"),
    ("magento", "Magento", "E-commerce", "high"),
    ("prestashop", "PrestaShop", "E-commerce", "high"),
    ("ghost", "Ghost", "CMS", "high"),
    ("hugo", "Hugo", "Static site generator", "low"),
    ("jekyll", "Jekyll", "Static site generator", "low"),
    ("gatsby", "Gatsby", "Static site generator", "high"),
    ("next.js", "Next.js", "Framework", "high"),
    ("nuxt", "Nuxt", "Framework", "high"),
    ("gatsbyimage", "Gatsby", "Framework", "high"),
    # --- frontend libraries, from script paths ---
    ("jquery", "jQuery", "Library", "high"),
    ("bootstrap", "Bootstrap", "CSS framework", "high"),
    ("tailwind", "Tailwind CSS", "CSS framework", "high"),
    ("react", "React", "Library", "high"),
    ("vue", "Vue.js", "Library", "high"),
    ("angular", "Angular", "Framework", "high"),
    ("svelte", "Svelte", "Framework", "high"),
    ("jquery.min.js", "jQuery", "Library", "high"),
    ("modernizr", "Modernizr", "Library", "high"),
    # --- analytics and tag managers ---
    ("google-analytics", "Google Analytics", "Analytics", "high"),
    ("googletagmanager", "Google Tag Manager", "Tag manager", "high"),
    ("gtag/js", "Google Analytics", "Analytics", "high"),
    ("gtm.js", "Google Tag Manager", "Tag manager", "high"),
    ("clarity.ms", "Microsoft Clarity", "Analytics", "high"),
    ("segment.com", "Segment", "Analytics", "high"),
    ("hotjar", "Hotjar", "Analytics", "high"),
    ("matomo", "Matomo", "Analytics", "high"),
    ("_paq", "Plausible", "Analytics", "low"),
    # --- hosting and platforms ---
    ("cloudfunctions", "Google Cloud Functions", "Platform", "low"),
    ("herokuapp", "Heroku", "Hosting", "high"),
    ("netlify", "Netlify", "Hosting", "high"),
    ("vercel", "Vercel", "Hosting", "high"),
    ("fly.io", "Fly.io", "Hosting", "low"),
    ("amazonaws", "Amazon Web Services", "Hosting", "low"),
    ("windows-nt", "Windows", "Platform", "low"),
)

_META_RE = re.compile(
    r"<meta[^>]+name=[\"'](?P<name>generator|Generator)[\"'][^>]*"
    r"content=[\"'](?P<content>[^\"']+)[\"']",
    re.IGNORECASE,
)
_META_REVERSED_RE = re.compile(
    r"<meta[^>]+content=[\"'](?P<content>[^\"']+)[\"'][^>]*"
    r"name=[\"'](?P<name>generator)[\"']",
    re.IGNORECASE,
)
_INCLUDE_RE = re.compile(
    r"""<(?:script[^>]+src|link[^>]+href)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def _generator(html: str) -> str:
    """Extract the ``generator`` meta tag, in either attribute order."""
    for pattern in (_META_RE, _META_REVERSED_RE):
        match = pattern.search(html)
        if match:
            return match.group("content").strip()
    return ""


def _includes(html: str, limit: int = 200) -> list[str]:
    """Return script and stylesheet URLs referenced by the page."""
    seen: list[str] = []
    for match in _INCLUDE_RE.finditer(html):
        url = match.group(1).strip()
        if url and url not in seen:
            seen.append(url)
        if len(seen) >= limit:
            break
    return seen


def detect(headers: dict[str, str], html: str = "") -> dict[str, Any]:
    """Fingerprint technologies from response headers and HTML.

    Args:
        headers: Response headers with lowercased keys.
        html: Optional response body, truncated internally to a sane size.

    Returns:
        A dict with a sorted ``technologies`` list of
        ``{name, category, confidence, evidence}``, a ``generator`` string, and
        a ``count``.
    """
    haystack_headers = "\n".join(
        f"{key}: {value}" for key, value in sorted(headers.items())
    ).lower()
    body = html[:MAX_HTML_BYTES]
    haystack_html = body.lower()
    generator = _generator(body)
    includes = _includes(body)
    haystack_includes = "\n".join(includes).lower()

    found: dict[str, dict[str, Any]] = {}

    def record(name: str, category: str, confidence: str, evidence: str) -> None:
        entry = found.get(name)
        if entry is None or (entry["confidence"] == "low" and confidence == "high"):
            found[name] = {
                "name": name,
                "category": category,
                "confidence": confidence,
                "evidence": evidence,
            }

    for needle, name, category, confidence in SIGNATURES:
        if needle in haystack_headers:
            record(name, category, confidence, f"header matched {needle!r}")
        elif needle in haystack_html:
            record(name, category, confidence, f"html matched {needle!r}")
        elif needle in haystack_includes:
            record(name, category, confidence, f"asset URL matched {needle!r}")

    technologies = sorted(found.values(), key=lambda item: (item["category"], item["name"]))
    return {
        "technologies": technologies,
        "count": len(technologies),
        "generator": generator,
        "asset_count": len(includes),
    }


def lookup(
    domain: str,
    context: ReconContext | None = None,
    session: Any = None,
) -> dict[str, Any]:
    """Fingerprint the technologies used by ``domain``.

    Reuses a single HTTP request: the body fetched for the ``http`` module is
    re-read here rather than fetched twice, keeping the tool to one GET per
    host.

    Args:
        domain: A normalized domain name.
        context: Shared run settings; supplies the per-request timeout.
        session: Optional prebuilt session, mainly for tests.

    Returns:
        The :func:`detect` output, or an ``error`` key when the site could not
        be reached. Never raises.
    """
    from . import http_info

    ctx = context or default_context()
    active = session or http_info.build_session(ctx)
    owns_session = session is None

    try:
        try:
            response = active.get(f"https://{domain}", timeout=ctx.timeout)
        except Exception as exc:  # broad by design: never break the run
            LOGGER.debug("fingerprint request to %s failed: %s", domain, exc)
            return {"error": f"could not fetch {domain} for fingerprinting: {exc}"}

        headers = {key.lower(): value for key, value in response.headers.items()}
        try:
            html = response.text[:MAX_HTML_BYTES]
        except (UnicodeDecodeError, AttributeError):
            html = ""
        return detect(headers, html)
    finally:
        if owns_session:
            active.close()
