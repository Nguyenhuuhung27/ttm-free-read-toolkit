"""Offline tests cho `ttm_staging_audit.py` — mock HTTP, KHONG network that.

    python -m unittest discover -s tests -v

Kiem tra:
  - prerequisite gating fail-closed (thieu env / production host / cookie trung nhau)
  - khong log cookie/token, khong luu body
  - ws1/ws3 dung entitlement state, khong suy tu HTTP 200
  - ws2 khong tu ket luan IDOR
  - ws4 phat hien audioUrl ma khong luu URL
  - ws5 co fingerprint build
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ttm_staging_audit as sa  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
FREE_HTML = (FIX / "free_chapter.html").read_text(encoding="utf-8")
LOCKED_HTML = (FIX / "locked_chapter.html").read_text(encoding="utf-8")
EMPTY_JSON = b'{"favorites":[]}'
# Classifier yeu cau body > 200 ky tu de coi A la "that su co entitlement".
# Keo dai synthetic body (van la noi dung gia) de test duong dan co entitlement.
LONG_PAD = "SYNTHETIC-PADDING-" * 20
FREE_HTML_LONG = FREE_HTML.replace("Dong ba ket thuc.",
                                   "Dong ba ket thuc. " + LONG_PAD)


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.content = body
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}


def fake_get_factory(mapping: dict):
    """Tra response theo (path, cookie_fp). Khong can requests that."""
    calls = []

    def _get(self, url, headers=None, timeout=None, allow_redirects=False):
        from urllib.parse import urlparse
        path = urlparse(url).path + (("?" + urlparse(url).query) if urlparse(url).query else "")
        ck = self.headers.get("Cookie", "")
        who = "anon" if not ck else ("A" if ck == "COOKIE_A" else "B")
        calls.append((who, path))
        key = (who, path)
        if key in mapping:
            return mapping[key]
        # Khong co response rieng cho who nay: tra JSON rong an toan.
        # (Khong fallback sang response cua anon, neu khong A se nhan nham
        #  body cua B va lam sai ket luan entitlement.)
        return FakeResponse(EMPTY_JSON, headers={"Content-Type": "application/json"})
    return _get, calls


def stub_harness(mapping: dict):
    """Tao Harness voi session gia, khong goi network, khong doc env that."""
    env = {k: "x" for k in sa.REQUIRED}
    env.update({"TTM_STAGING_URL": "https://staging.example.test",
                "TTM_COOKIE_A": "COOKIE_A", "TTM_COOKIE_B": "COOKIE_B"})
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch.object(sa, "DELAY", 0), \
         mock.patch.object(sa.requests.Session, "get", new=fake_get_factory(mapping)[0]):
        h = sa.Harness("https://staging.example.test", False,
                       Path("recon/_unit_staging.json"))
        # thay session that bang session gia co header Cookie danh nhan
        for who, ck in (("A", "COOKIE_A"), ("B", "COOKIE_B"), ("anon", "")):
            s = mock.Mock()
            s.headers = {"Cookie": ck} if ck else {}
            s.get = fake_get_factory(mapping)[0].__get__(s, type(s))
            h.sessions[who] = s
        return h


class TestPrerequisites(unittest.TestCase):
    def test_missing_all_env_refuses(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            pr = sa.prerequisites()
        self.assertFalse(pr["ready"])
        self.assertEqual(len(pr["missing"]), len(sa.REQUIRED))
        self.assertEqual(sa.die(pr), 3)

    def test_production_host_refused(self):
        env = {"TTM_STAGING_URL": "https://tieuthuyetmang.com"}
        with mock.patch.dict(os.environ, env, clear=True):
            ok, msg = sa.staging_host_ok(os.environ["TTM_STAGING_URL"])
        self.assertFalse(ok)
        self.assertIn("TU CHOI", msg)

    def test_production_subdomain_refused(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, _ = sa.staging_host_ok("https://api.tieuthuyetmang.com")
        self.assertFalse(ok)

    def test_staging_host_accepted(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, host = sa.staging_host_ok("https://staging.example.test")
        self.assertTrue(ok)
        self.assertEqual(host, "staging.example.test")

    def test_localhost_http_accepted(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, _ = sa.staging_host_ok("http://localhost:3000")
        self.assertTrue(ok)

    def test_identical_cookies_not_independent(self):
        env = {k: "x" for k in sa.REQUIRED}
        env.update({"TTM_STAGING_URL": "https://staging.example.test",
                    "TTM_COOKIE_A": "same", "TTM_COOKIE_B": "same"})
        with mock.patch.dict(os.environ, env, clear=True):
            pr = sa.prerequisites()
        self.assertFalse(pr["sessions_independent"])
        self.assertFalse(pr["ready"])

    def test_full_prereqs_but_no_run_still_no_network(self):
        env = {k: "x" for k in sa.REQUIRED}
        env.update({"TTM_STAGING_URL": "https://staging.example.test",
                    "TTM_COOKIE_A": "aaa", "TTM_COOKIE_B": "bbb"})
        with mock.patch.dict(os.environ, env, clear=True):
            pr = sa.prerequisites()
            self.assertTrue(pr["ready"])
            # env chi co do dai, khong co gia tri nhiem vu
            self.assertNotIn("aaa", json.dumps(pr))

    def test_env_state_logs_length_only(self):
        env = {k: "supersecretvalue" for k in sa.REQUIRED}
        with mock.patch.dict(os.environ, env, clear=True):
            s = sa.env_state()
        self.assertTrue(all(isinstance(v, int) for v in s.values()))
        self.assertNotIn("supersecretvalue", json.dumps(s))

    def test_redact_cookie_and_bearer(self):
        out = sa.redact("__Host-next-auth.csrf-token=abcdef123456; Bearer xyz987654321")
        self.assertNotIn("abcdef123456", out)
        self.assertNotIn("xyz987654321", out)


class TestWorkstreamsWithMocks(unittest.TestCase):
    """Chay 5 workstream voi response synthetic, khong network."""

    def setUp(self):
        free = FakeResponse(FREE_HTML_LONG.encode("utf-8"))
        locked = FakeResponse(LOCKED_HTML.encode("utf-8"))
        self.cfg = {"slug": "synthetic-story", "chapter": "1",
                    "chapter_id": "01SYNTHETIC0000000000000",
                    "story_id": "01SYNTHETICSTORY00000000"}
        doc = "/truyen/synthetic-story/doc/1.html"
        nghe = "/truyen/synthetic-story/nghe/1.html"
        self.mapping = {
            ("A", doc): free, ("B", doc): locked, ("anon", doc): locked,
            ("A", nghe): free, ("B", nghe): locked, ("anon", nghe): locked,
            ("/api/favorites" if False else "x", "x"): free,
        }
        for w in ("A", "B", "anon"):
            for p in ("/api/favorites", "/api/notifications",
                      "/api/listening-history",
                      "/api/user/audio-remaining", "/sitemap.xml", "/api/config"):
                self.mapping[(w, p)] = FakeResponse(EMPTY_JSON, headers={
                    "Content-Type": "application/json", "Cache-Control": "private, no-store",
                    "cf-cache-status": "DYNAMIC"})
            self.mapping[(w, "/api/listening-history?chapterId=01SYNTHETIC0000000000000")] = \
                FakeResponse(EMPTY_JSON, headers={"Content-Type": "application/json"})
            self.mapping[(w, "/api/chapters/01SYNTHETIC0000000000000/comments")] = \
                FakeResponse(EMPTY_JSON, headers={"Content-Type": "application/json"})
            for suf in ("", ".json", ".txt", ".css", ".png", ".",
                        ".xhtml", "%2Ehtml"):
                # Bo qua ".html": path do trung voi doc path cua ws1/ws3,
                # phai giu response theo entitlement (A=free, B/anon=locked).
                self.mapping[(w, "/truyen/synthetic-story/doc/1" + suf)] = locked

    def _h(self):
        return stub_harness(self.mapping)

    def test_ws1_entitled_a_and_isolated_b(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws1_session_isolation(self._h(), self.cfg)
        self.assertTrue(out["A_entitled"])
        self.assertFalse(out["B_received_A_body"])
        self.assertEqual(out["props"]["B"]["content_state"], "LOCKED_NO_PROTECTED_DATA")
        self.assertNotIn(sa.UNKNOWN, out["status"])
        self.assertIsNone(json.dumps(out).find("COOKIE_A") if "COOKIE_A" in json.dumps(out) else None)

    def test_ws1_never_puts_cookie_in_evidence(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws1_session_isolation(self._h(), self.cfg)
        self.assertFalse(out["rows"]["A"]["cookie_logged"])
        self.assertEqual(len(out["rows"]["A"]["body_sha256"]), 16)

    def test_ws2_does_not_claim_idor(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(self._h(), self.cfg)
        self.assertEqual(out["status"], sa.UNKNOWN)
        self.assertIn("favorites", out["objects"])
        self.assertIn("listening-history", out["objects"])
        self.assertIn("comments", out["objects"])
        for name, rec in out["objects"].items():
            self.assertFalse(rec["needs_review"])

    def test_ws3_classifier_unknown_when_a_not_entitled(self):
        m = dict(self.mapping)
        doc = "/truyen/synthetic-story/doc/1.html"
        m[("A", doc)] = FakeResponse(LOCKED_HTML.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            h = stub_harness(m)
            out = sa.ws3_cache_isolation(h, self.cfg)
        self.assertEqual(out["status"], sa.UNKNOWN)
        self.assertIn("UNKNOWN", out["classifier_result"])

    def test_ws3_isolated_when_a_entitled(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws3_cache_isolation(self._h(), self.cfg)
        self.assertFalse(out["cache_hit_seen"])
        self.assertTrue(out["b_distinct_from_a"])
        self.assertEqual(out["classifier_result"], "OBSERVED_ISOLATED")

    def test_ws3_detects_leak_synthetic(self):
        m = dict(self.mapping)
        doc = "/truyen/synthetic-story/doc/1.html"
        m[("B", doc)] = FakeResponse(FREE_HTML_LONG.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws3_cache_isolation(stub_harness(m), self.cfg)
        self.assertEqual(out["classifier_result"], "OBSERVED_CROSS_SESSION_LEAK")
        self.assertFalse(out["b_distinct_from_a"])

    def test_ws4_audio_signals_no_url_logged(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws4_audio_entitlement(self._h(), self.cfg)
        self.assertTrue(out["consistent_with_entitlement"])
        self.assertFalse(out["data"]["B"]["signals"]["media_urls_logged"])
        self.assertNotIn("https://", json.dumps(out["data"]["B"]["signals"]))

    def test_ws5_matcher_has_fingerprint(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws5_matcher(self._h(), self.cfg)
        self.assertEqual(len(out["probes"]), 9)
        self.assertIn("sitemap", out["fingerprint"])
        self.assertIn("config", out["fingerprint"])
        # Khong tu dong ket luan vulnerability: note phai co menh de phu dinh.
        self.assertIn("khong ket luan", out["note"].lower())
        self.assertNotIn("confirmed vulnerability", out["note"].lower())

    def test_plan_writes_no_secrets_and_refuses_run(self):
        # Capture output thay vi ghi vao repo: unit test khong duoc co side effect
        # (truoc day lam recon/staging_plan.json bi dirty sau moi lan chay).
        captured = {}

        def fake_write(self, text, *a, **kw):
            captured["text"] = text
            return len(text)

        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(sa.Path, "write_text", new=fake_write), \
             mock.patch.object(sys, "argv", ["ttm_staging_audit.py",
                                             "--plan", "--write-plan"]):
            rc = sa.main()
        self.assertEqual(rc, 3)
        plan = json.loads(captured["text"])
        self.assertFalse(plan["prerequisites"]["ready"])
        self.assertNotIn("supersecret", captured["text"])

    def test_plain_plan_does_not_touch_evidence_file(self):
        """`--plan` mac dinh chi in ra stdout, khong ghi de file da commit."""
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(sa.Path, "write_text") as w, \
             mock.patch.object(sys, "argv", ["ttm_staging_audit.py", "--plan"]):
            rc = sa.main()
        self.assertEqual(rc, 3)
        w.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
