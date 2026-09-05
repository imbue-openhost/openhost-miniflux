#!/usr/bin/env python3
"""Subscribe a fresh Miniflux installation to app-defined feeds."""

from __future__ import annotations

import argparse
import http.cookies
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _SubscriptionFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.csrf = ""
        self.category_id = ""
        self._in_category_select = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "input" and values.get("name") == "csrf":
            self.csrf = values.get("value") or ""
        elif tag == "select" and values.get("name") == "category_id":
            self._in_category_select = True
        elif tag == "option" and self._in_category_select and not self.category_id:
            self.category_id = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._in_category_select = False


def _open(opener, request: urllib.request.Request, expected: set[int]):
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        if error.code not in expected:
            raise
        response = error

    if response.status not in expected:
        raise RuntimeError(f"Miniflux returned HTTP {response.status} for {request.full_url}")
    return response


def _cookie_header(headers) -> str:
    cookies: dict[str, str] = {}
    for value in headers.get_all("Set-Cookie", []):
        parsed = http.cookies.SimpleCookie()
        parsed.load(value)
        for name, morsel in parsed.items():
            # Miniflux rotates the anonymous session during proxy login and
            # sends the replacement cookie with the same name.
            cookies[name] = morsel.value
    if not cookies:
        raise RuntimeError("Miniflux did not create an authentication session")
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def subscribe(feed_urls: list[str], base_url: str = "http://127.0.0.1:8081") -> None:
    opener = urllib.request.build_opener(_NoRedirect())
    login = urllib.request.Request(
        urllib.parse.urljoin(base_url, "/"),
        headers={"X-Openhost-User": "admin"},
    )
    with _open(opener, login, {302}) as response:
        cookie = _cookie_header(response.headers)

    export = urllib.request.Request(
        urllib.parse.urljoin(base_url, "/export"), headers={"Cookie": cookie}
    )
    with _open(opener, export, {200}) as response:
        existing = {
            element.attrib["xmlUrl"]
            for element in ET.fromstring(response.read()).iter("outline")
            if "xmlUrl" in element.attrib
        }

    for feed_url in feed_urls:
        if feed_url in existing:
            continue

        form_request = urllib.request.Request(
            urllib.parse.urljoin(base_url, "/subscribe"), headers={"Cookie": cookie}
        )
        with _open(opener, form_request, {200}) as response:
            parser = _SubscriptionFormParser()
            parser.feed(response.read().decode("utf-8"))

        if not parser.csrf or not parser.category_id:
            raise RuntimeError("Could not read the Miniflux subscription form")

        body = urllib.parse.urlencode(
            {"csrf": parser.csrf, "url": feed_url, "category_id": parser.category_id}
        ).encode()
        create = urllib.request.Request(
            urllib.parse.urljoin(base_url, "/subscribe"),
            data=body,
            headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"},
        )
        with _open(opener, create, {302}) as response:
            location = response.headers.get("Location", "")
        if not location.startswith("/feed/") or not location.endswith("/entries"):
            raise RuntimeError(f"Miniflux did not subscribe to {feed_url}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("feed_url", nargs="+")
    parser.add_argument("--port", default="8081")
    args = parser.parse_args()
    subscribe(args.feed_url, f"http://127.0.0.1:{args.port}")


if __name__ == "__main__":
    main()
