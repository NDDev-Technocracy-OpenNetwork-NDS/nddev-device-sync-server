"""Real server cookie-adapter acceptance using the owning isolated SMTP/PG fixture.

This verifies the HTTP adapter; actual browser cookie/storage behavior has a
separate browser acceptance gate. No production identities or databases enter it.
"""
from http.cookies import SimpleCookie
import json
import urllib.error
import urllib.request


def check_browser(origin, owner, code, messages, sql):
    assert origin.startswith(("http://127.0.0.1:", "http://localhost:"))
    assert owner.endswith("@example.invalid")
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    standard = {"X-NDS-Client": "browser", "Origin": origin, "Sec-Fetch-Site": "same-origin"}

    def request(path, body=None, method=None, cookie=None, replace=None, native=False):
        headers = {} if native else dict(standard)
        if cookie is not None:
            headers["Cookie"] = cookie
        for key, value in (replace or {}).items():
            if value is None:
                headers.pop(key, None)
            else:
                headers[key] = value
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(origin + path, data=None if body is None else json.dumps(body).encode(), method=method, headers=headers)
        try:
            response = http.open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            assert len(raw) <= 65536
            assert response.headers["Cache-Control"] == "no-store"
            return response.status, json.loads(raw) if raw else None, response.headers

    assert request("/v2/browser", native=True)[:2] == (200, {"session_mode": "cookie", "device_platform": "web", "replica_protocol": 2})
    sql("DELETE FROM nds_auth_limits; DELETE FROM nds_email_challenges;")
    count = len(messages()) + 1
    status, challenge, _ = request("/v2/auth/email/challenges", {"email": owner})
    assert status == 202
    otp = code(count)
    status, issued, headers = request("/v2/auth/email/verify", {"challenge_id": challenge["challenge_id"], "code": otp})
    assert status == 200 and set(issued) == {"session"}
    cookies = SimpleCookie()
    cookies.load(headers["Set-Cookie"])
    session = cookies["__Host-nds-session"]
    assert session["secure"] and session["httponly"] and session["samesite"] == "Strict"
    assert session["path"] == "/" and not session["domain"]
    assert 0 < int(session["max-age"]) <= 604800
    token = session.value
    cookie = "__Host-nds-session=" + token
    assert token not in json.dumps(issued)
    assert request("/v2/session", cookie=cookie)[:2] == (200, issued["session"])
    assert request("/v2/session", cookie=cookie, native=True)[0] == 401
    for change in [{"Origin": "https://foreign.example.invalid"}, {"Origin": "null"},
                   {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
                   {"Authorization": "Bearer " + token}, {"X-NDS-Client": "unknown"}]:
        assert request("/v2/session", cookie=cookie, replace=change)[0] == 400
    assert request("/v2/session", cookie=cookie + "; " + cookie)[0] == 400
    assert request("/v2/session", method="DELETE", cookie=cookie, replace={"Origin": None})[0] == 400
    assert request("/v2/session", cookie=cookie)[0] == 200
    assert request("/v2/sync/operations?after_seq=0&limit=1", cookie=cookie)[:2] == (400, {"error": "invalid_signature"})
    status, _, headers = request("/v2/session", method="DELETE", cookie=cookie)
    assert status == 204 and "Max-Age=0" in headers["Set-Cookie"]
    status, _, headers = request("/v2/session", cookie=cookie)
    assert status == 401 and "Max-Age=0" in headers["Set-Cookie"]
    print("Browser HTTP adapter acceptance passed: real OTP/SQL issuance, credential-free JSON, cookie attributes, origin/credential ambiguity rejection, independent device proof, logout and replay denial.")
    return [token, otp]
