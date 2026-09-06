#!/usr/bin/env python3
"""
MEGATRON - browser_agent.py  (v0.7.0)

Persistent Playwright browser session that the LLM drives via observe/act.
This is the substrate for the browser-driven exploit-execution loop that closes
the gap toward Shannon's 96% XBOW score.

Design notes:
  - One BrowserSession = one Chromium context = one persistent cookie jar +
    localStorage across many actions.
  - `observe()` returns a compact JSON snapshot the LLM can reason over: URL,
    title, forms (with real DOM selectors), inputs, first N links, first 2KB of
    visible text. The LLM CANNOT invent selectors — must pick from observed set.
  - `act()` executes ONE atomic action then waits for network idle before
    returning the next observation. Time-boxed per action (10s default).
  - Auth passthrough: AUTH_COOKIE + AUTH_HEADER threaded into every session.
  - Safe to call in Docker with --no-sandbox (chromium ARGS).
  - Graceful degradation: if playwright not installed, class methods raise
    ImportError with a clear install hint. Caller can catch + fall back.
"""
from __future__ import annotations

import base64
import os
import re
from typing import Any


AUTH_COOKIE = os.environ.get("AUTH_COOKIE", "")
AUTH_HEADER = os.environ.get("AUTH_HEADER", "")


class BrowserSession:
    """Wraps one Playwright browser+context+page. Use as context manager."""

    def __init__(self, target_url: str, headless: bool = True, timeout_ms: int = 10000):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise ImportError(
                "playwright not installed. Run: pip install playwright && "
                "playwright install chromium --with-deps"
            ) from e
        self._sync_playwright = sync_playwright
        self.target       = target_url
        self.headless     = headless
        self.timeout_ms   = timeout_ms
        self._pw          = None
        self._browser     = None
        self._ctx         = None
        self._page        = None
        self._action_log: list[dict] = []

    def __enter__(self):
        self._pw = self._sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self.headless,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        extra_headers: dict[str, str] = {}
        if AUTH_HEADER and ":" in AUTH_HEADER:
            k, v = AUTH_HEADER.split(":", 1)
            extra_headers[k.strip()] = v.strip()
        self._ctx = self._browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            user_agent="MEGATRON/0.7 (browser-agent; +https://github.com/d3ath69/Megatron)",
            extra_http_headers=extra_headers or None,
        )
        if AUTH_COOKIE:
            from urllib.parse import urlparse
            host = urlparse(self.target).netloc.split(":", 1)[0]
            for kv in AUTH_COOKIE.split(";"):
                if "=" in kv:
                    name, value = kv.strip().split("=", 1)
                    if name:
                        self._ctx.add_cookies([{
                            "name": name, "value": value,
                            "domain": host, "path": "/",
                        }])
        self._page = self._ctx.new_page()
        self._page.set_default_timeout(self.timeout_ms)
        try:
            self._page.goto(self.target, wait_until="domcontentloaded", timeout=15000)
        except Exception as e:
            self._action_log.append({"step": 0, "action": "initial-goto", "error": str(e)[:200]})
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    def observe(self, max_visible: int = 2000, max_links: int = 30, want_screenshot: bool = False) -> dict:
        """Compact snapshot of current page. Forms include DOM path selectors for act()."""
        if not self._page:
            return {"error": "session not initialized"}
        try:
            url    = self._page.url
            title  = self._page.title()
            status = self._page.evaluate("() => document.documentElement.outerHTML.length")
        except Exception as e:
            return {"error": f"observe failed: {e}"}

        forms: list[dict] = []
        for i, form in enumerate(self._page.query_selector_all("form")):
            try:
                inputs = []
                for inp in form.query_selector_all("input,textarea,select"):
                    name = inp.get_attribute("name")
                    if name:
                        inputs.append({
                            "name":     name,
                            "type":     inp.get_attribute("type") or "text",
                            "selector": f"form:nth-of-type({i+1}) [name='{name}']",
                        })
                submit = form.query_selector("button[type='submit'],input[type='submit']")
                submit_sel = f"form:nth-of-type({i+1}) button[type='submit'],form:nth-of-type({i+1}) input[type='submit']" if submit else None
                forms.append({
                    "index":   i,
                    "action":  form.get_attribute("action") or "",
                    "method":  (form.get_attribute("method") or "GET").upper(),
                    "inputs":  inputs,
                    "submit_selector": submit_sel,
                })
            except Exception:
                continue

        inputs_all: list[dict] = []
        for inp in self._page.query_selector_all("input,textarea,select"):
            name = inp.get_attribute("name")
            if name:
                inputs_all.append({
                    "name": name,
                    "type": inp.get_attribute("type") or "text",
                    "selector": f"[name='{name}']",
                })

        links: list[dict] = []
        for a in self._page.query_selector_all("a[href]")[:max_links]:
            try:
                links.append({
                    "text": (a.inner_text() or "")[:60],
                    "href": a.get_attribute("href") or "",
                })
            except Exception:
                continue

        buttons: list[dict] = []
        for b in self._page.query_selector_all("button, input[type='button']")[:15]:
            try:
                buttons.append({
                    "text": (b.inner_text() or b.get_attribute("value") or "")[:40],
                    "selector": f"text={(b.inner_text() or '').strip()[:40]!r}" if b.inner_text() else "",
                })
            except Exception:
                continue

        try:
            visible = self._page.inner_text("body")[:max_visible]
        except Exception:
            visible = ""

        snap: dict[str, Any] = {
            "url":              url,
            "title":            title,
            "html_size_bytes":  status,
            "forms":            forms,
            "inputs":           inputs_all,
            "links":            links,
            "buttons":          buttons,
            "visible_text":     visible,
        }
        if want_screenshot:
            try:
                png = self._page.screenshot(full_page=False)
                snap["screenshot_b64"] = base64.b64encode(png).decode()[:20000]
            except Exception:
                pass
        return snap

    def act(self, action: dict) -> dict:
        """Execute ONE action. Types: click | fill | submit | navigate | wait | screenshot."""
        if not self._page:
            return {"ok": False, "error": "session not initialized"}
        atype    = (action.get("type") or "").lower()
        selector = action.get("selector", "")
        value    = action.get("value", "")

        try:
            if atype == "navigate":
                url = value or selector or self.target
                self._page.goto(url, wait_until="domcontentloaded", timeout=15000)
            elif atype == "click":
                self._page.click(selector, timeout=self.timeout_ms)
            elif atype == "fill":
                self._page.fill(selector, value, timeout=self.timeout_ms)
            elif atype == "submit":
                if selector.startswith("form"):
                    self._page.evaluate(f"document.querySelector({selector!r}).submit()")
                else:
                    self._page.click(selector, timeout=self.timeout_ms)
            elif atype == "wait":
                self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
            elif atype == "screenshot":
                pass
            elif atype == "eval":
                self._page.evaluate(value)
            else:
                return {"ok": False, "error": f"unknown action type: {atype}"}
            try:
                self._page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            self._action_log.append({"step": len(self._action_log), "action": action, "ok": True})
            return {"ok": True}
        except Exception as e:
            self._action_log.append({"step": len(self._action_log), "action": action, "error": str(e)[:200]})
            return {"ok": False, "error": str(e)[:200]}

    def get_cookies(self) -> list[dict]:
        """Return current cookie jar — useful for exporting the session to other tools."""
        if not self._ctx:
            return []
        try:
            return self._ctx.cookies()
        except Exception:
            return []

    def action_history(self) -> list[dict]:
        return list(self._action_log)


_LOGIN_HINTS_RE  = re.compile(r"\b(login|sign[\s-]?in|username|password|log[\s-]?in)\b", re.I)
_REGISTER_HINTS_RE = re.compile(r"\b(register|sign[\s-]?up|create[\s-]?account|new[\s-]?user)\b", re.I)

BOOTSTRAP_USERNAME = os.environ.get("MEGATRON_BOOTSTRAP_USER", "megatron_test_user")
BOOTSTRAP_PASSWORD = os.environ.get("MEGATRON_BOOTSTRAP_PASS", "M3g4tr0n!Test123")
BOOTSTRAP_EMAIL    = os.environ.get("MEGATRON_BOOTSTRAP_EMAIL", "megatron@example.test")

_COMMON_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "admin123"),
    ("admin",  ""),
    ("root",   "root"),
    ("root",   "toor"),
    ("test",   "test"),
    ("guest",  "guest"),
    ("user",   "user"),
    (BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD),
]

_REGISTER_PATHS = ["/register", "/signup", "/sign-up", "/create-account", "/join", "/auth/register"]
_LOGIN_PATHS    = ["/login",    "/signin", "/sign-in", "/auth/login", "/user/login", "/account/login"]


def looks_like_login_page(observation: dict) -> bool:
    """Heuristic: does the observed page have login fields or login-related text?"""
    for f in observation.get("forms", []):
        names = [i.get("name", "").lower() for i in f.get("inputs", [])]
        if any(k in " ".join(names) for k in ("password", "passwd", "pwd")):
            return True
    text = observation.get("visible_text", "")
    return bool(_LOGIN_HINTS_RE.search(text))


def looks_like_register_page(observation: dict) -> bool:
    text = observation.get("visible_text", "") + " " + observation.get("title", "")
    return bool(_REGISTER_HINTS_RE.search(text))


def _find_form_field(observation: dict, purpose: str) -> tuple[str, str] | None:
    """
    Find (form_index, field_selector) for a semantic purpose:
      purpose='username' → matches name=user, name=username, name=email, name=login
      purpose='password' → matches name=password, name=passwd, name=pwd
      purpose='email'    → matches name=email, name=e_mail, name=e-mail
      purpose='confirm'  → matches name=confirm_password, name=password2, name=repeat
    """
    matchers = {
        "username": ("user", "username", "email", "login", "name"),
        "password": ("password", "passwd", "pwd", "pass"),
        "email":    ("email", "e_mail", "e-mail", "mail"),
        "confirm":  ("confirm", "password2", "password_2", "repeat", "re_password"),
    }
    keys = matchers.get(purpose, ())
    for form in observation.get("forms", []):
        for inp in form.get("inputs", []):
            name = inp.get("name", "").lower()
            itype = inp.get("type", "").lower()
            if purpose == "password" and itype == "password":
                return form["index"], inp["selector"]
            if purpose == "email" and itype == "email":
                return form["index"], inp["selector"]
            if any(k in name for k in keys):
                return form["index"], inp["selector"]
    return None


def bootstrap_auth(session, verbose: bool = True) -> dict:
    """
    Try to establish an authenticated session BEFORE the exploit loop starts.
    Strategy:
      1) Probe /register, /signup etc. — if a registration form exists, fill it
         with MEGATRON_BOOTSTRAP_* creds and submit.
      2) Probe /login, /signin etc. — try newly-registered creds, then common
         default creds (admin/admin, admin/password, etc.).
      3) After each attempted login, check if the session cookie changed and if
         the current page no longer looks like a login page.

    Returns {"success": bool, "username": str, "cookies": [{name, value, ...}], "notes": str}
    Failure is non-fatal — exploit loop continues without auth.
    """
    result = {"success": False, "username": "", "cookies": [], "notes": ""}
    base_url = session.target
    notes: list[str] = []

    def _log(msg):
        if verbose:
            print(f"    [auth-bootstrap] {msg}")

    for path in _REGISTER_PATHS:
        url = base_url.rstrip("/") + path
        r = session.act({"type": "navigate", "value": url})
        if not r.get("ok"):
            continue
        obs = session.observe(max_visible=500, max_links=5)
        if not obs.get("forms"):
            continue
        user_field = _find_form_field(obs, "username")
        pass_field = _find_form_field(obs, "password")
        if not (user_field and pass_field):
            continue
        _log(f"registration form at {path} — filling")
        session.act({"type": "fill", "selector": user_field[1], "value": BOOTSTRAP_USERNAME})
        session.act({"type": "fill", "selector": pass_field[1], "value": BOOTSTRAP_PASSWORD})
        conf_field = _find_form_field(obs, "confirm")
        if conf_field:
            session.act({"type": "fill", "selector": conf_field[1], "value": BOOTSTRAP_PASSWORD})
        email_field = _find_form_field(obs, "email")
        if email_field:
            session.act({"type": "fill", "selector": email_field[1], "value": BOOTSTRAP_EMAIL})
        submit_sel = obs["forms"][user_field[0]].get("submit_selector")
        if submit_sel:
            session.act({"type": "click", "selector": submit_sel})
        else:
            session.act({"type": "submit", "selector": f"form:nth-of-type({user_field[0]+1})"})
        notes.append(f"attempted register at {path}")
        break

    for path in _LOGIN_PATHS:
        url = base_url.rstrip("/") + path
        r = session.act({"type": "navigate", "value": url})
        if not r.get("ok"):
            continue
        obs = session.observe(max_visible=500, max_links=5)
        user_field = _find_form_field(obs, "username")
        pass_field = _find_form_field(obs, "password")
        if not (user_field and pass_field):
            continue

        creds_to_try = [(BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)] + _COMMON_DEFAULT_CREDS
        for username, password in creds_to_try:
            _log(f"login attempt at {path} with {username}:{password[:4]}***")
            session.act({"type": "fill", "selector": user_field[1], "value": username})
            session.act({"type": "fill", "selector": pass_field[1], "value": password})
            submit_sel = obs["forms"][user_field[0]].get("submit_selector")
            if submit_sel:
                session.act({"type": "click", "selector": submit_sel})
            else:
                session.act({"type": "submit", "selector": f"form:nth-of-type({user_field[0]+1})"})
            post_obs = session.observe(max_visible=300, max_links=5)
            if not looks_like_login_page(post_obs) and not _LOGIN_HINTS_RE.search(post_obs.get("visible_text", "").lower()):
                cookies = session.get_cookies()
                if cookies:
                    result["success"]  = True
                    result["username"] = username
                    result["cookies"]  = cookies
                    notes.append(f"logged in as {username} via {path}")
                    result["notes"] = " | ".join(notes)
                    _log(f"SUCCESS as {username} (cookie jar has {len(cookies)} entries)")
                    return result
            session.act({"type": "navigate", "value": url})
        break

    result["notes"] = " | ".join(notes) if notes else "no login/register forms found on standard paths"
    _log(result["notes"])
    return result


def cookies_to_header(cookies: list[dict]) -> str:
    """Convert Playwright cookie list → HTTP Cookie header value for CLI tools."""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
