#!/usr/bin/env python3
"""Exercise the local Compose OAuth flow using only the Python standard library."""

import http.client
import http.cookiejar
import json
import socket
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


APP = "http://envoy.holepunch.localwormhole:3128"
SECOND_APP = "http://app.holepunch.localwormhole:3128"
AUTH = "http://auth.holepunch.localwormhole:3128"
CALLBACK = "/-/wormhole/oauthmngr"
SESSION = "_wormhole_session"
BINDING = "_wormhole_oauth_flow_"
LOCAL_ENDPOINTS = {
    ("envoy.holepunch.localwormhole", 3128),
    ("app.holepunch.localwormhole", 3128),
    ("auth.holepunch.localwormhole", 3128),
    ("dex.holepunch.localwormhole", 5556),
    ("127.0.0.1", 8082),
    ("127.0.0.1", 3128),
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class LocalConnection(http.client.HTTPConnection):
    def connect(self):
        require((self.host, self.port) in LOCAL_ENDPOINTS, "Unexpected OAuth destination")
        self.sock = socket.create_connection(("127.0.0.1", self.port), self.timeout)


class LocalHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request):
        return self.do_open(LocalConnection, request)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action", ""), "inputs": {}}
            self.forms.append(self.current)
        elif tag in ("input", "button") and self.current is not None:
            if "name" in attrs:
                self.current["inputs"][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class Browser:
    def __init__(self):
        policy = http.cookiejar.DefaultCookiePolicy(
            strict_ns_domain=http.cookiejar.DefaultCookiePolicy.DomainStrictNonDomain
        )
        self.cookies = http.cookiejar.CookieJar(policy)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            LocalHTTPHandler(),
            urllib.request.HTTPCookieProcessor(self.cookies),
            NoRedirect(),
        )

    def request(self, url, fields=None):
        require(urllib.parse.urlsplit(url).scheme == "http", "Expected local HTTP URL")
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        try:
            response = self.opener.open(urllib.request.Request(url, data=data), timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.code, response.headers, response.read()

    def login_callback(self, target, email="foo@example.com"):
        """Complete Dex login and capture, stopping before application redemption."""
        status, headers, _ = self.request(target)
        require(status == 302, f"Expected authentication redirect, got {status}")
        require("no-store" in headers.get("Cache-Control", ""), "Flow redirect is cacheable")
        bindings = [cookie for cookie in self.cookies if cookie.name.startswith(BINDING)]
        require(len(bindings) == 1, "Expected a nonce-specific browser binding cookie")
        binding = bindings[0]
        require(not binding.domain_specified, "Binding cookie must be host-only")
        require(binding.path == CALLBACK, "Incorrect binding cookie path")
        require(binding.has_nonstandard_attr("HttpOnly"), "Binding cookie lacks HttpOnly")
        require(binding.get_nonstandard_attr("SameSite") == "Lax", "Binding cookie lacks SameSite=Lax")
        require(not binding.secure, "HTTP development binding must not require HTTPS")
        require(290 < binding.expires - time.time() <= 300, "Expected five-minute binding lifetime")
        url = urllib.parse.urljoin(target, headers["Location"])
        credentials_submitted = False
        for _ in range(20):
            parsed = urllib.parse.urlsplit(url)
            if parsed.netloc == urllib.parse.urlsplit(target).netloc and parsed.path == CALLBACK:
                proxy_sessions = [c for c in self.cookies if c.name == "_oauth2_proxy"]
                require(len(proxy_sessions) == 1, "Expected oauth2-proxy session on auth host")
                proxy_cookie = proxy_sessions[0]
                require(
                    proxy_cookie.domain == urllib.parse.urlsplit(AUTH).hostname
                    and not proxy_cookie.domain_specified,
                    "oauth2-proxy session must be host-only on the auth host",
                )
                return url, binding
            status, headers, body = self.request(url)
            if status in (301, 302, 303, 307, 308):
                url = urllib.parse.urljoin(url, headers["Location"])
                continue
            require(status == 200, f"OAuth login step returned {status} on {parsed.hostname}")
            require(parsed.hostname == "dex.holepunch.localwormhole", "Expected Dex login page")
            parser = FormParser()
            parser.feed(body.decode())
            forms = [
                form for form in parser.forms
                if "password" in form["inputs"] or form["inputs"].get("approval") == "approve"
            ]
            require(len(forms) == 1, "Expected a Dex login or approval form")
            form = forms[0]
            fields = form["inputs"]
            if "login" in fields and "password" in fields:
                require(not credentials_submitted, "Dex rejected the development credentials")
                fields.update(login=email, password="password")
                credentials_submitted = True
            else:
                require("approval" in fields, "Unrecognized Dex form")
                fields["approval"] = "approve"
            action = urllib.parse.urljoin(url, form["action"])
            require(urllib.parse.urlsplit(action).hostname == parsed.hostname, "Unexpected form host")
            status, headers, _ = self.request(action, fields)
            require(status in (302, 303), f"Dex form submission returned {status}")
            url = urllib.parse.urljoin(action, headers["Location"])
        raise AssertionError("OAuth redirect limit exceeded")

    def redeem(self, callback, target):
        status, headers, _ = self.request(callback)
        require(status == 302, f"Application callback returned {status}")
        require(headers["Location"] == target, "Original path/query was not restored")
        require("no-store" in headers.get("Cache-Control", ""), "Callback is cacheable")
        host = urllib.parse.urlsplit(target).hostname
        sessions = [c for c in self.cookies if c.name == SESSION and c.domain == host]
        require(len(sessions) == 1, "Application session was not issued")
        cookie = sessions[0]
        require(not cookie.domain_specified and cookie.path == "/", "Session is not host-only at /")
        require(cookie.has_nonstandard_attr("HttpOnly"), "Session lacks HttpOnly")
        require(cookie.get_nonstandard_attr("SameSite") == "Lax", "Session lacks SameSite=Lax")
        require(not cookie.secure, "HTTP development session must not require HTTPS")
        require(43100 < cookie.expires - time.time() <= 43200, "Expected 12-hour session lifetime")
        require(not any(c.name.startswith(BINDING) for c in self.cookies), "Binding cookie was not expired")


class LocalAuthFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        browser = Browser()
        deadline = time.monotonic() + 120
        last_error = "services not ready"
        while time.monotonic() < deadline:
            try:
                status, _, _ = browser.request("http://127.0.0.1:3128/ping")
                login_status, _, _ = browser.request(APP + "/whoami")
                if status == 200 and login_status == 302:
                    return
                last_error = f"ping={status}, app={login_status}"
            except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
                last_error = type(error).__name__
            time.sleep(2)
        raise AssertionError(f"Local deployment not ready after 120s: {last_error}; run make dev-up")

    def test_login_host_isolation_replay_and_invalid_session(self):
        browser = Browser()
        target = APP + "/whoami?local_auth_test=1"
        callback, _ = browser.login_callback(target)
        browser.redeem(callback, target)
        status, _, body = browser.request(target)
        self.assertEqual(status, 200)
        upstream = json.loads(body)
        self.assertIn("X-Token", upstream)
        self.assertNotIn(SESSION, upstream.get("Cookie", ""))
        self.assertNotIn("_oauth2_proxy", upstream.get("Cookie", ""))
        self.assertEqual(browser.request(callback)[0], 401, "Callback replay was accepted")

        second = SECOND_APP + "/whoami"
        callback, _ = browser.login_callback(second)
        browser.redeem(callback, second)
        self.assertEqual(browser.request(second)[0], 200)
        self.assertEqual(browser.request(target)[0], 200)
        sessions = [c for c in browser.cookies if c.name == SESSION]
        self.assertEqual(len(sessions), 2)
        next(c for c in sessions if c.domain == urllib.parse.urlsplit(APP).hostname).value = "invalid"
        status, headers, _ = browser.request(target)
        self.assertEqual(status, 302, "Invalid sessions must initiate a new login")
        self.assertTrue(headers["Location"].startswith(AUTH + "/-/wormhole/oauth2/start?"))

    def test_missing_or_incorrect_browser_proof_consumes_flow(self):
        for proof in ("missing", "incorrect"):
            with self.subTest(proof=proof):
                browser = Browser()
                callback, binding = browser.login_callback(APP + "/whoami")
                original_value = binding.value
                if proof == "missing":
                    browser.cookies.clear(binding.domain, binding.path, binding.name)
                else:
                    binding.value = "incorrect"
                self.assertEqual(browser.request(callback)[0], 401)
                self.assertFalse(any(c.name == SESSION for c in browser.cookies))
                self.assertFalse(any(c.name.startswith(BINDING) for c in browser.cookies))
                binding.value = original_value
                browser.cookies.set_cookie(binding)
                self.assertEqual(browser.request(callback)[0], 401, "Rejected flow was not consumed")

    def test_token_exchange_denial(self):
        browser = Browser()
        target = APP + "/whoami"
        callback, _ = browser.login_callback(target, email="bar@example.com")
        browser.redeem(callback, target)
        status, _, _ = browser.request(target)
        self.assertIn(status, (401, 403), "bar must not receive upstream access")

    def test_routes_and_existing_token_access(self):
        browser = Browser()
        status, _, body = browser.request("http://127.0.0.1:8082/api/v1/state/ctls")
        self.assertEqual(status, 200)
        routes = list(json.loads(body).values())
        self.assertEqual(
            {route["kind"] for route in routes},
            {"upstream", "oauth2-proxy", "oauth-callback", "reserved"},
        )
        for base in (APP, SECOND_APP):
            host = urllib.parse.urlsplit(base).hostname
            kinds = {r["kind"] for r in routes if r["source"] == host}
            self.assertEqual(kinds, {"upstream", "oauth-callback", "reserved"})
            self.assertEqual(browser.request(base + "/-/wormhole/oauth2/start")[0], 404)
            self.assertEqual(browser.request(base + "/-/wormhole/not-a-route")[0], 404)
        self.assertEqual(browser.request(AUTH + CALLBACK)[0], 400)
        request = urllib.request.Request(
            APP + "/whoami",
            headers={"X-Token": "c520c08c-0325-48c4-8bd1-57bde8c7c382.foo"},
        )
        with browser.opener.open(request, timeout=10) as response:
            self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
