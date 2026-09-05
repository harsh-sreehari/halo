"""Anti-CSRF token harvester and request injector."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Typical CSRF cookie identifiers
CSRF_COOKIE_NAMES = (
    "xsrf-token",
    "csrf_token",
    "_csrf",
    "csrf-token",
    "csrftoken",
    "xsrf_token",
    "_csrf_token",
    "laravel_session",
)

# Typical CSRF header identifiers
CSRF_HEADER_NAMES = (
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "xsrf-token",
    "x-csrftoken",
)

# Meta tag patterns for HTML scraping
CSRF_META_PATTERNS = [
    re.compile(
        r"""<meta\s+[^>]*name=["'](?:csrf-token|csrf_token|_csrf|csrf-param|xsrf-token|xsrf_token)["'][^>]*content=["']([^"']+)["']""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["'](?:csrf-token|csrf_token|_csrf|csrf-param|xsrf-token|xsrf_token)["']""",
        re.IGNORECASE,
    ),
]

# Form hidden input patterns for HTML scraping
CSRF_INPUT_PATTERNS = [
    re.compile(
        r"""<input\s+[^>]*name=["'](?:_csrf|csrf_token|csrf-token|authenticity_token|__RequestVerificationToken|_token)["'][^>]*value=["']([^"']+)["']""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""<input\s+[^>]*value=["']([^"']+)["'][^>]*name=["'](?:_csrf|csrf_token|csrf-token|authenticity_token|__RequestVerificationToken|_token)["']""",
        re.IGNORECASE,
    ),
]


class CSRFHarvester:
    """Extracts anti-CSRF tokens from cookies, headers, or HTML and injects them into downstream requests."""

    def __init__(self, default_header_name: str = "X-CSRF-Token") -> None:
        self.default_header_name = default_header_name
        self.last_token: str | None = None

    def extract_from_headers(self, headers: httpx.Headers | dict[str, str] | Any) -> str | None:
        """Extract CSRF token from Set-Cookie or direct CSRF response headers."""
        # 1. Direct CSRF headers
        if hasattr(headers, "get_list"):
            # httpx.Headers supports get_list
            for header_name in CSRF_HEADER_NAMES:
                val = headers.get(header_name)
                if val:
                    self.last_token = val
                    return val

            set_cookie_headers = headers.get_list("set-cookie")
        else:
            headers_dict = dict(headers)
            set_cookie_headers = []
            for k, v in headers_dict.items():
                k_lower = k.lower()
                if k_lower in CSRF_HEADER_NAMES and v:
                    self.last_token = v
                    return v
                if k_lower == "set-cookie" and v:
                    if isinstance(v, list):
                        set_cookie_headers.extend([str(item) for item in v])
                    else:
                        set_cookie_headers.append(str(v))

        # 2. Extract from Set-Cookie headers
        for cookie_str in set_cookie_headers:
            if not cookie_str:
                continue
            # Each Set-Cookie can be formatted as key=value; Path=/; etc.
            cookie_parts = cookie_str.split(";")
            for part in cookie_parts:
                part = part.strip()
                if "=" in part:
                    cookie_name, cookie_val = part.split("=", 1)
                    if cookie_name.strip().lower() in CSRF_COOKIE_NAMES and cookie_val.strip():
                        token = cookie_val.strip()
                        self.last_token = token
                        return token

        return None

    def extract_from_html(self, html: str) -> str | None:
        """Extract CSRF token from HTML meta tags or hidden inputs."""
        if not html:
            return None

        # 1. Check meta tags
        for pattern in CSRF_META_PATTERNS:
            match = pattern.search(html)
            if match:
                token = match.group(1).strip()
                if token:
                    self.last_token = token
                    return token

        # 2. Check hidden inputs
        for pattern in CSRF_INPUT_PATTERNS:
            match = pattern.search(html)
            if match:
                token = match.group(1).strip()
                if token:
                    self.last_token = token
                    return token

        return None

    def extract_token(self, response: httpx.Response) -> str | None:
        """Extract anti-CSRF token from response cookies, headers, or HTML body."""
        # 1. Check response cookies safely
        try:
            if hasattr(response, "cookies"):
                for cookie_name in CSRF_COOKIE_NAMES:
                    for c_name, c_val in response.cookies.items():
                        if c_name.lower() == cookie_name and c_val:
                            self.last_token = c_val
                            return c_val
        except (RuntimeError, AttributeError):
            logger.debug("Response cookies could not be accessed directly")

        # 2. Check response headers (including Set-Cookie headers)
        if hasattr(response, "headers"):
            token = self.extract_from_headers(response.headers)
            if token:
                return token

        # 3. Check response body if text/html or json
        try:
            content_type = response.headers.get("content-type", "").lower() if hasattr(response, "headers") else ""
            if "html" in content_type or not content_type:
                text = response.text
                html_token = self.extract_from_html(text)
                if html_token:
                    return html_token
        except (httpx.HTTPError, UnicodeDecodeError, AttributeError) as err:
            logger.debug("Failed to parse HTML body for CSRF token: %s", err)

        return None

    def inject_csrf(
        self,
        headers: dict[str, str],
        token: str | None = None,
        header_name: str | None = None,
    ) -> dict[str, str]:
        """Inject the anti-CSRF token into the request headers dictionary."""
        effective_token = token or self.last_token
        effective_header = header_name or self.default_header_name
        if effective_token:
            headers[effective_header] = effective_token
        return headers

    def inject_headers(
        self,
        headers: dict[str, str],
        token: str | None = None,
        header_name: str | None = None,
    ) -> dict[str, str]:
        """Alias for inject_csrf."""
        return self.inject_csrf(headers, token, header_name)
