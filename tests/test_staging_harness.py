"""Offline tests cho `ttm_staging_audit.py` — mock HTTP, KHONG network that.

    python -m unittest discover -s tests -v

Kiem tra:
  - prerequisite gating fail-closed (thieu env / production host / cookie trung nhau)
  - allowlist host STRICT (exact match, khong substring) — regression D-1
  - abort ngay khi gap 403/429 — regression D-2
  - moi write bi chan khi thieu --allow-mutate / TTM_MUTATE_AUTHORIZED — D-3
  - WS1/WS3 so sanh FINGERPRINT NOI DUNG, khong hash toan response — D-4
  - WS4: A thieu audio -> UNKNOWN; B co audio -> NEEDS_REVIEW — D-5
  - WS2: pha 2 tao record synthetic, kiem tra quyen so huu — D-6
  - khong log cookie/token, khong luu body, khong luu audio URL
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ttm_staging_audit as sa  # noqa: E402
from audit_classify import (audio_entitlement_state, audio_signals,  # noqa: E402
                            cache_isolation_state, object_authz_state,
                            record_fingerprint)

FIX = Path(__file__).resolve().parent / "fixtures"
FREE_HTML = (FIX / "free_chapter.html").read_text(encoding="utf-8")
LOCKED_HTML = (FIX / "locked_chapter.html").read_text(encoding="utf-8")
EMPTY_JSON = b'{"favorites":[]}'
# Classifier yeu cau body > 200 ky tu de coi A la "that su co entitlement".
LONG_PAD = "SYNTHETIC-PADDING-" * 20
FREE_HTML_LONG = FREE_HTML.replace("Dong ba ket thuc.",
                                   "Dong ba ket thuc. " + LONG_PAD)

COOKIE_A = "synthetic-session-alpha-9f3c2b"
COOKIE_B = "synthetic-session-beta-7a1d4e"

# Dynamic metadata KHAC NHAU giua hai response, nhung noi dung protected
# GIONG HET -> hash toan response khac, fingerprint noi dung giong.
A_HTML = FREE_HTML_LONG.replace("<title>synthetic</title>",
                                 '<title>synthetic</title><script>var rid="A-1111"</script>')
B_HTML = FREE_HTML_LONG.replace("<title>synthetic</title>",
                                 '<title>synthetic</title><script>var rid="B-2222"</script>')

AUDIO_WITH_URL = ('<!DOCTYPE html><html><body><script>self.__next_f.push([1,'
                  '"{\\"audioUrl\\":\\"https://cdn.example.test/a.m4a\\"}"])'
                  '</script></body></html>')
AUDIO_MEDIA_ONLY = ('<!DOCTYPE html><html><body><script>self.__next_f.push([1,'
                    '"{\\"src\\":\\"https://cdn.example.test/b.mp3\\"}"])'
                    '</script></body></html>')
AUDIO_NULL_URL = ('<!DOCTYPE html><html><body><script>self.__next_f.push([1,'
                  '"{\\"audioUrl\\":null}"])'
                  '</script></body></html>')

READING_RECORD = json.dumps(
    {"readingHistory": [{"storyId": "01SYNTHETICSTORY00000000",
                         "chapterNumber": 1}]}).encode()
READING_EMPTY = json.dumps({"readingHistory": []}).encode()
# Ban ghi da bi B ghi de -> fingerprint phai khac ban ghi goc.
MODIFIED_RECORD = json.dumps(
    {"readingHistory": [{"storyId": "01SYNTHETICSTORY00000000",
                         "chapterNumber": 1, "position": 99}]}).encode()


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.content = body
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}


def dispatch_factory(mapping: dict):
    """Tra response theo (method, who, path). Khong can requests that."""
    calls = []

    def _dispatch(session, method, url, **kw):
        u = urlparse(url)
        path = u.path + (("?" + u.query) if u.query else "")
        ck = session.headers.get("Cookie", "")
        who = "anon" if not ck else ("A" if ck == COOKIE_A else "B")
        calls.append((method, who, path))
        for key in ((method, who, path), (method, path)):
            if key in mapping:
                val = mapping[key]
                # Gia tri co the la callable -> mock co trang thai.
                if callable(val):
                    return val(who, path, method)
                return val
        return FakeResponse(EMPTY_JSON, headers={"Content-Type": "application/json"})

    return _dispatch, calls


def stub_harness(mapping: dict, *, allow_mutate: bool = False,
                 mutate_authorized: bool = False):
    """Tao Harness voi session gia, khong goi network, khong doc env that."""
    env = {k: "x" for k in sa.REQUIRED}
    env.update({"TTM_STAGING_URL": "https://staging.example.test",
                "TTM_ALLOWED_STAGING_HOSTS": "staging.example.test",
                "TTM_COOKIE_A": COOKIE_A, "TTM_COOKIE_B": COOKIE_B})
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch.object(sa, "DELAY", 0), \
         mock.patch.object(sa.requests.Session, "get", new=mock.Mock()), \
         mock.patch.object(sa.requests.Session, "post", new=mock.Mock()):
        h = sa.Harness("https://staging.example.test", allow_mutate,
                       Path("recon/_unit_staging.json"),
                       mutate_authorized=mutate_authorized,
                       verified_host="staging.example.test")
        dispatch, calls = dispatch_factory(mapping)
        for who, ck in (("A", COOKIE_A), ("B", COOKIE_B), ("anon", "")):
            s = mock.Mock()
            s.headers = {"Cookie": ck} if ck else {}
            # Bind `s` NOW: closure neu se tro toi bien cuoi vong lap (anon).
            s.get = lambda url, _s=s, **kw: dispatch(_s, "GET", url, **kw)
            s.post = lambda url, _s=s, **kw: dispatch(_s, "POST", url, **kw)
            h.sessions[who] = s
        h._calls = calls
        return h


class TestPrerequisites(unittest.TestCase):
    """Gating fail-closed + allowlist STRICT."""

    def test_missing_all_env_refuses(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(sys, "argv", ["ttm_staging_audit.py", "--run"]):
            rc = sa.main()
        self.assertEqual(rc, 3)

    def test_production_host_refused(self):
        ok, msg = sa.staging_host_ok("https://tieuthuyetmang.com", set())
        self.assertFalse(ok)
        self.assertIn("production", msg)

    def test_production_subdomain_refused(self):
        ok, msg = sa.staging_host_ok("https://api.tieuthuyetmang.com", set())
        self.assertFalse(ok)
        self.assertIn("production", msg)

    def test_production_refused_even_if_allowlisted(self):
        """Allowlist khong duoc duoc dung de mo production."""
        ok, msg = sa.staging_host_ok(
            "https://tieuthuyetmang.com", {"tieuthuyetmang.com"})
        self.assertFalse(ok)
        self.assertIn("production", msg)

    def test_localhost_http_accepted(self):
        ok, _ = sa.staging_host_ok("http://127.0.0.1:8080", set())
        self.assertTrue(ok)

    def test_remote_host_requires_exact_allowlist_entry(self):
        ok, _ = sa.staging_host_ok("https://staging.example.test",
                                   {"staging.example.test"})
        self.assertTrue(ok)

    # --- regression D-1: substring matching la khong du ---
    def test_substring_host_without_allowlist_is_refused(self):
        """"evil-staging.example.test" KHONG duoc phep neu khong nam exact
        trong allowlist — truoc day substring matching se cho qua."""
        ok, msg = sa.staging_host_ok("https://evil-staging.example.test", set())
        self.assertFalse(ok)
        self.assertIn("allowlist", msg)

    def test_allowlist_is_exact_not_suffix_or_substring(self):
        allow = {"staging.example.test"}
        for host in ("notstaging.example.test", "staging.example.test.evil.com",
                     "example.test", "x-staging.example.test"):
            ok, _ = sa.staging_host_ok(f"https://{host}", allow)
            self.assertFalse(ok, f"{host} phai bi tu choi")

    def test_remote_host_requires_https(self):
        ok, msg = sa.staging_host_ok("http://staging.example.test",
                                     {"staging.example.test"})
        self.assertFalse(ok)
        self.assertIn("https", msg)

    def test_identical_cookies_not_independent(self):
        with mock.patch.dict(os.environ, {"TTM_COOKIE_A": "same",
                                           "TTM_COOKIE_B": "same"}, clear=True):
            pr = sa.prerequisites()
        self.assertFalse(pr["sessions_independent"])
        self.assertFalse(pr["ready"])

    def test_full_prereqs_but_no_run_still_no_network(self):
        """Prereq du day du nhung khong co --run -> KHONG duoc gui request nao."""
        env = {k: "x" for k in sa.REQUIRED}
        env.update({"TTM_STAGING_URL": "https://staging.example.test",
                    "TTM_ALLOWED_STAGING_HOSTS": "staging.example.test",
                    "TTM_COOKIE_A": "a", "TTM_COOKIE_B": "b"})
        boom = mock.Mock(side_effect=AssertionError("network called!"))
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(sa.requests.Session, "get", boom), \
             mock.patch.object(sa.requests.Session, "post", boom), \
             mock.patch.object(sys, "argv", ["ttm_staging_audit.py"]):
            rc = sa.main()
        self.assertEqual(rc, 0)   # ready=true -> plan exit 0, van khong network
        self.assertFalse(boom.called)

    def test_env_state_logs_length_only(self):
        with mock.patch.dict(os.environ, {"TTM_COOKIE_A": "supersecretvalue"},
                             clear=True):
            st = sa.env_state()
        self.assertEqual(st["TTM_COOKIE_A"], len("supersecretvalue"))
        self.assertNotIn("supersecretvalue", json.dumps(st))

    def test_redact_cookie_and_bearer(self):
        out = sa.redact("__Host-sess=abcdef123456; Bearer abcdefghijklmnop")
        self.assertNotIn("abcdef123456", out)
        self.assertNotIn("abcdefghijklmnop", out)


class TestAudioSignals(unittest.TestCase):
    """Regression D-5: phat hien ca audioUrl property va media reference."""

    def test_detects_audio_url_property_with_value(self):
        sig = audio_signals(AUDIO_WITH_URL)
        self.assertTrue(sig["audioUrl_prop_present"])
        self.assertTrue(sig["audioUrl_prop_has_value"])
        self.assertTrue(sig["has_audio"])
        self.assertEqual(sig["media_ref_count"], 1)

    def test_detects_media_reference_without_audio_url_property(self):
        sig = audio_signals(AUDIO_MEDIA_ONLY)
        self.assertFalse(sig["audioUrl_prop_present"])
        self.assertTrue(sig["media_ref_present"])
        self.assertTrue(sig["has_audio"])

    def test_null_audio_url_is_not_a_signal(self):
        sig = audio_signals(AUDIO_NULL_URL)
        self.assertTrue(sig["audioUrl_prop_present"])
        self.assertFalse(sig["audioUrl_prop_has_value"])
        self.assertFalse(sig["has_audio"])

    def test_no_audio_at_all(self):
        sig = audio_signals(LOCKED_HTML)
        self.assertFalse(sig["has_audio"])
        self.assertEqual(sig["media_ref_count"], 0)

    def test_url_is_never_returned_or_stored(self):
        sig = audio_signals(AUDIO_WITH_URL)
        blob = json.dumps(sig)
        self.assertNotIn("cdn.example.test", blob)
        self.assertNotIn("a.m4a", blob)
        self.assertFalse(sig["media_refs_logged"])


class TestAudioEntitlementState(unittest.TestCase):
    """Regression D-5: verdict audio phai phan biet UNKNOWN voi thanh cong."""

    def test_a_without_audio_is_unknown_not_success(self):
        state = audio_entitlement_state(a_has_audio=False, b_has_audio=False)
        self.assertEqual(state, "UNKNOWN_A_NO_AUDIO")
        self.assertTrue(state.startswith("UNKNOWN"))

    def test_b_with_audio_needs_review(self):
        state = audio_entitlement_state(a_has_audio=True, b_has_audio=True)
        self.assertEqual(state, "OBSERVED_NEEDS_REVIEW")

    def test_a_with_audio_and_b_without_is_consistent(self):
        state = audio_entitlement_state(a_has_audio=True, b_has_audio=False)
        self.assertEqual(state, "OBSERVED_CONSISTENT")

    def test_not_entitled_a_is_unknown(self):
        state = audio_entitlement_state(a_has_audio=False, b_has_audio=False,
                                        a_entitled=False)
        self.assertEqual(state, "UNKNOWN_A_NOT_ENTITLED")

    def test_missing_signal_is_unknown(self):
        state = audio_entitlement_state(a_has_audio=None, b_has_audio=False)
        self.assertEqual(state, "UNKNOWN_MISSING_SIGNAL")


class TestObjectAuthzState(unittest.TestCase):
    """Regression D-6: verdict quyen so huu object."""

    def test_no_record_is_unknown(self):
        self.assertEqual(object_authz_state(record_created=False),
                         "UNKNOWN_NO_SYNTHETIC_RECORD")

    def test_b_reading_a_record_needs_review(self):
        self.assertEqual(
            object_authz_state(record_created=True, a_can_read=True,
                               b_can_read=True, anon_rejected=True),
            "OBSERVED_NEEDS_REVIEW")

    def test_b_writing_a_record_needs_review(self):
        self.assertEqual(
            object_authz_state(record_created=True, a_can_read=True,
                               b_can_read=False, anon_rejected=True,
                               b_write_accepted=True, a_record_unchanged=False),
            "OBSERVED_NEEDS_REVIEW")

    def test_isolated_when_b_cannot_read(self):
        self.assertEqual(
            object_authz_state(record_created=True, a_can_read=True,
                               b_can_read=False, anon_rejected=True,
                               b_write_accepted=False, a_record_unchanged=True),
            "OBSERVED_ISOLATED")


class TestRecordFingerprint(unittest.TestCase):
    def test_counts_entries_without_storing_content(self):
        fp = record_fingerprint(READING_RECORD)
        self.assertEqual(fp["count"], 1)
        self.assertEqual(len(fp["sha256"]), 16)
        self.assertNotIn("chapterNumber", json.dumps(fp))

    def test_empty_list(self):
        self.assertEqual(record_fingerprint(READING_EMPTY)["count"], 0)

    def test_non_json_is_handled(self):
        fp = record_fingerprint(b"<html>not json</html>")
        self.assertFalse(fp["parsed"])


class TestCacheIsolationPrefersContentFingerprint(unittest.TestCase):
    """Regression D-4: so sanh noi dung, khong hash toan response."""

    def test_content_sha_preferred_over_body_sha(self):
        rows = [{"label": "A", "locked": False, "body_chars": 500,
                 "content_sha": "aaaa1111", "body_sha": "bbbb2222"},
                {"label": "B", "locked": True, "body_chars": 500,
                 "content_sha": "aaaa1111", "body_sha": "cccc3333"}]
        self.assertEqual(cache_isolation_state(session_rows=rows,
                                               cache_hit_seen=False),
                         "OBSERVED_CROSS_SESSION_LEAK")

    def test_body_sha_still_supported(self):
        rows = [{"label": "A", "locked": False, "body_chars": 500,
                 "body_sha": "same"},
                {"label": "B", "locked": True, "body_chars": 500,
                 "body_sha": "same"}]
        self.assertEqual(cache_isolation_state(session_rows=rows,
                                               cache_hit_seen=False),
                         "OBSERVED_CROSS_SESSION_LEAK")


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
        self.mapping = {}
        for w in ("A", "B", "anon"):
            for p in ("/api/reading-history", "/api/favorites",
                      "/api/notifications", "/api/listening-history",
                      "/api/user/audio-remaining", "/sitemap.xml", "/api/config"):
                self.mapping[("GET", w, p)] = FakeResponse(EMPTY_JSON, headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "private, no-store",
                    "cf-cache-status": "DYNAMIC"})
            self.mapping[("GET", w, "/api/listening-history?chapterId=01SYNTHETIC0000000000000")] = \
                FakeResponse(EMPTY_JSON, headers={"Content-Type": "application/json"})
            self.mapping[("GET", w, "/api/chapters/01SYNTHETIC0000000000000/comments")] = \
                FakeResponse(EMPTY_JSON, headers={"Content-Type": "application/json"})
            for suf in ("", ".json", ".txt", ".css", ".png", ".",
                        ".xhtml", "%2Ehtml"):
                # Bo qua ".html": path do trung voi doc path cua ws1/ws3,
                # phai giu response theo entitlement (A=free, B/anon=locked).
                self.mapping[("GET", w, "/truyen/synthetic-story/doc/1" + suf)] = locked
        self.mapping[("GET", "A", doc)] = free
        self.mapping[("GET", "B", doc)] = locked
        self.mapping[("GET", "anon", doc)] = locked
        for w in ("A", "B", "anon"):
            self.mapping[("GET", w, nghe)] = locked

    def _h(self, **kw):
        return stub_harness(self.mapping, **kw)

    # ------------------------------------------------------------ WS1
    def test_ws1_entitled_a_and_isolated_b(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws1_session_isolation(self._h(), self.cfg)
        self.assertTrue(out["A_entitled"])
        self.assertFalse(out["B_received_A_body"])
        self.assertEqual(out["props"]["B"]["content_state"],
                         "LOCKED_NO_PROTECTED_DATA")
        self.assertNotIn(sa.UNKNOWN, out["status"])

    def test_ws1_never_puts_cookie_in_evidence(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws1_session_isolation(self._h(), self.cfg)
        self.assertFalse(out["rows"]["A"]["cookie_logged"])
        self.assertEqual(len(out["rows"]["A"]["body_sha256"]), 16)

    # --- regression D-4: leak bi bo sot khi metadata dong khac nhau ---
    def test_ws1_detects_leak_despite_dynamic_metadata(self):
        m = dict(self.mapping)
        doc = "/truyen/synthetic-story/doc/1.html"
        m[("GET", "A", doc)] = FakeResponse(A_HTML.encode("utf-8"))
        m[("GET", "B", doc)] = FakeResponse(B_HTML.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws1_session_isolation(stub_harness(m), self.cfg)
        # Hash TOAN response khac nhau (nen cach so sanh cu khong bat duoc)...
        self.assertNotEqual(out["rows"]["A"]["body_sha256"],
                            out["rows"]["B"]["body_sha256"])
        # ...nhung fingerprint NOI DUNG giong -> leak phai bi phat hien.
        self.assertEqual(out["content_fingerprints"]["A"]["sha256"],
                         out["content_fingerprints"]["B"]["sha256"])
        self.assertTrue(out["B_received_A_body"])
        self.assertEqual(out["status"], "OBSERVED_NEEDS_REVIEW")

    def test_ws1_content_fingerprint_is_independent_of_metadata(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws1_session_isolation(self._h(), self.cfg)
        cfp = out["content_fingerprints"]
        self.assertEqual(len(cfp["A"]["sha256"]), 16)
        self.assertTrue(cfp["A"]["synthetic_marker_present"])
        self.assertFalse(cfp["B"]["synthetic_marker_present"])

    # ------------------------------------------------------------ WS2
    def test_ws2_read_only_phase_performs_no_write(self):
        """--allow-mutate phai chan MOI write, khong chi write co the gan."""
        h = self._h(allow_mutate=False, mutate_authorized=False)
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(h, self.cfg)
        self.assertEqual(h.writes, [])
        self.assertFalse(out["write_phase"]["executed"])
        self.assertEqual(out["write_phase"]["status"], sa.UNKNOWN)
        self.assertTrue(all(r["method"] == "GET" for r in h.rows))

    def test_ws2_does_not_claim_idor(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(self._h(), self.cfg)
        self.assertEqual(out["status"], sa.UNKNOWN)
        self.assertIn("reading-history", out["objects"])
        self.assertIn("favorites", out["objects"])
        self.assertIn("listening-history", out["objects"])
        self.assertIn("comments", out["objects"])
        self.assertIn("audio-remaining", out["objects"])
        self.assertEqual(len(out["objects"]), 6)
        for name, rec in out["objects"].items():
            self.assertFalse(rec["needs_review"], name)

    def test_ws2_flags_cross_session_data_for_reading_history(self):
        m = dict(self.mapping)
        for w in ("A", "B"):
            m[("GET", w, "/api/reading-history")] = FakeResponse(
                READING_RECORD, headers={"Content-Type": "application/json"})
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(stub_harness(m), self.cfg)
        rec = out["objects"]["reading-history"]
        self.assertTrue(rec["a_has_session_specific_data"])
        self.assertTrue(rec["b_equals_a"])
        self.assertTrue(rec["needs_review"])
        self.assertEqual(rec["status"], "OBSERVED_NEEDS_REVIEW")
        self.assertEqual(out["status"], sa.UNKNOWN)

    def test_ws2_identical_empty_records_are_not_flagged(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(self._h(), self.cfg)
        rec = out["objects"]["reading-history"]
        self.assertFalse(rec["a_has_session_specific_data"])
        self.assertFalse(rec["needs_review"])
        self.assertEqual(rec["status"], "UNKNOWN_NO_SESSION_SPECIFIC_DATA")

    # --- regression D-6: phase 2 kiem tra quyen so huu ---
    def _mutating_mapping(self, *, b_reads_a: bool = False,
                          b_write_status: int = 403,
                          anon_status: int = 401,
                          b_overwrites_a: bool = False):
        """Mock co trang thai: neu B ghi duoc va server ghi de record cua A
        thi lan GET tiep cua A tra ve record DA DOI."""
        m = dict(self.mapping)
        state = {"b_wrote": False}

        def a_view(who, path, method):
            if state["b_wrote"] and b_overwrites_a:
                return FakeResponse(MODIFIED_RECORD,
                                    headers={"Content-Type": "application/json"})
            return FakeResponse(READING_RECORD,
                                headers={"Content-Type": "application/json"})

        def b_post(who, path, method):
            if 200 <= b_write_status < 300:
                state["b_wrote"] = True
            return FakeResponse(b'{"ok":true}', status=b_write_status,
                                headers={"Content-Type": "application/json"})

        m[("POST", "A", "/api/reading-history")] = FakeResponse(
            b'{"ok":true}', status=200, headers={"Content-Type": "application/json"})
        m[("POST", "B", "/api/reading-history")] = b_post
        m[("GET", "A", "/api/reading-history")] = a_view
        m[("GET", "B", "/api/reading-history")] = FakeResponse(
            READING_RECORD if b_reads_a else READING_EMPTY,
            headers={"Content-Type": "application/json"})
        m[("GET", "anon", "/api/reading-history")] = FakeResponse(
            b'{"error":"unauthorized"}', status=anon_status,
            headers={"Content-Type": "application/json"})
        return m

    def test_ws2_write_phase_creates_record_and_checks_ownership(self):
        h = stub_harness(self._mutating_mapping(), allow_mutate=True,
                         mutate_authorized=True)
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(h, self.cfg)
        rec = out["write_phase"]["records"]["reading-history"]
        self.assertTrue(out["write_phase"]["executed"])
        self.assertTrue(rec["record_created"])
        self.assertTrue(rec["a_can_read"])
        self.assertFalse(rec["b_can_read"])
        self.assertTrue(rec["anon_rejected"])
        self.assertFalse(rec["b_write_accepted"])
        self.assertTrue(rec["a_record_unchanged"])
        self.assertEqual(rec["status"], "OBSERVED_ISOLATED")
        # Hai write da duoc ghi nhan (A tao, B thu sua)
        self.assertEqual(len(h.writes), 2)
        self.assertTrue(all(w["write_authorized"] for w in h.writes))

    def test_ws2_write_phase_flags_b_reading_a_record(self):
        h = stub_harness(self._mutating_mapping(b_reads_a=True),
                         allow_mutate=True, mutate_authorized=True)
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(h, self.cfg)
        rec = out["write_phase"]["records"]["reading-history"]
        self.assertTrue(rec["b_can_read"])
        self.assertEqual(rec["status"], "OBSERVED_NEEDS_REVIEW")

    def test_ws2_write_phase_flags_b_modifying_a_record(self):
        """B ghi duoc VA lam record cua A doi -> can review."""
        h = stub_harness(self._mutating_mapping(b_write_status=200,
                                                b_overwrites_a=True),
                         allow_mutate=True, mutate_authorized=True)
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(h, self.cfg)
        rec = out["write_phase"]["records"]["reading-history"]
        self.assertTrue(rec["b_write_accepted"])
        self.assertFalse(rec["a_record_unchanged"])
        self.assertEqual(rec["status"], "OBSERVED_NEEDS_REVIEW")

    def test_ws2_write_phase_b_write_accepted_but_a_unchanged_is_isolated(self):
        """B ghi duoc nhung server gan record theo owner -> A khong doi.
        Day la hanh vi CACH LY DUNG, khong phai can review."""
        h = stub_harness(self._mutating_mapping(b_write_status=200),
                         allow_mutate=True, mutate_authorized=True)
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(h, self.cfg)
        rec = out["write_phase"]["records"]["reading-history"]
        self.assertTrue(rec["b_write_accepted"])
        self.assertTrue(rec["a_record_unchanged"])
        self.assertEqual(rec["status"], "OBSERVED_ISOLATED")

    # ------------------------------------------------------------ WS3
    def test_ws3_classifier_unknown_when_a_not_entitled(self):
        m = dict(self.mapping)
        doc = "/truyen/synthetic-story/doc/1.html"
        m[("GET", "A", doc)] = FakeResponse(LOCKED_HTML.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws3_cache_isolation(stub_harness(m), self.cfg)
        self.assertEqual(out["status"], sa.UNKNOWN)
        self.assertIn("UNKNOWN", out["classifier_result"])

    def test_ws3_isolated_when_a_entitled(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws3_cache_isolation(self._h(), self.cfg)
        self.assertEqual(out["status"], sa.OBSERVED)
        self.assertEqual(out["classifier_result"], "OBSERVED_ISOLATED")

    def test_ws3_detects_leak_synthetic(self):
        m = dict(self.mapping)
        doc = "/truyen/synthetic-story/doc/1.html"
        for w in ("A", "B"):
            m[("GET", w, doc)] = FakeResponse(FREE_HTML_LONG.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws3_cache_isolation(stub_harness(m), self.cfg)
        self.assertEqual(out["classifier_result"], "OBSERVED_CROSS_SESSION_LEAK")
        self.assertEqual(out["status"], sa.OBSERVED)

    # ------------------------------------------------------------ WS4
    def test_ws4_audio_signals_no_url_logged(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws4_audio_entitlement(self._h(), self.cfg, a_entitled=True)
        blob = json.dumps(out)
        self.assertNotIn("cdn.example.test", blob)
        self.assertFalse(out["data"]["A"]["signals"]["media_refs_logged"])

    def test_ws4_missing_audio_for_a_is_unknown(self):
        """Regression D-5: A thieu audio -> UNKNOWN, KHONG phai ket luan
        thanh cong. Truoc day logic cu tra OBSERVED khi ca hai deu 0."""
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws4_audio_entitlement(self._h(), self.cfg, a_entitled=True)
        self.assertEqual(out["audio_state"], "UNKNOWN_A_NO_AUDIO")
        self.assertEqual(out["status"], sa.UNKNOWN)

    def test_ws4_b_with_audio_needs_review(self):
        m = dict(self.mapping)
        nghe = "/truyen/synthetic-story/nghe/1.html"
        for w in ("A", "B"):
            m[("GET", w, nghe)] = FakeResponse(AUDIO_WITH_URL.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws4_audio_entitlement(stub_harness(m), self.cfg,
                                           a_entitled=True)
        self.assertTrue(out["a_has_audio"])
        self.assertTrue(out["b_has_audio"])
        self.assertEqual(out["audio_state"], "OBSERVED_NEEDS_REVIEW")
        self.assertEqual(out["status"], "OBSERVED_NEEDS_REVIEW")

    def test_ws4_a_with_audio_b_without_is_consistent(self):
        m = dict(self.mapping)
        nghe = "/truyen/synthetic-story/nghe/1.html"
        m[("GET", "A", nghe)] = FakeResponse(AUDIO_WITH_URL.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws4_audio_entitlement(stub_harness(m), self.cfg,
                                           a_entitled=True)
        self.assertEqual(out["audio_state"], "OBSERVED_CONSISTENT")
        self.assertEqual(out["status"], sa.OBSERVED)

    def test_ws4_media_reference_without_prop_is_detected(self):
        m = dict(self.mapping)
        nghe = "/truyen/synthetic-story/nghe/1.html"
        m[("GET", "A", nghe)] = FakeResponse(AUDIO_MEDIA_ONLY.encode("utf-8"))
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws4_audio_entitlement(stub_harness(m), self.cfg,
                                           a_entitled=True)
        self.assertTrue(out["a_has_audio"])

    # ------------------------------------------------------------ WS5
    def test_ws5_matcher_has_fingerprint(self):
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws5_matcher(self._h(), self.cfg)
        self.assertEqual(len(out["probes"]), 9)
        self.assertIn("sitemap", out["fingerprint"])
        self.assertIn("config", out["fingerprint"])

    # --------------------------------------------- abort / write gating
    def test_get_403_aborts_run(self):
        """Regression D-2: 403 tren session A/B -> dung NGAY.

        (403 cho anonymous la ket qua mong doi cua endpoint yeu cau dang nhap
        -> khong abort; xem test_expect_deny_403_does_not_abort.)"""
        m = dict(self.mapping)
        m[("GET", "A", "/api/favorites")] = FakeResponse(
            b"{}", status=403, headers={"Content-Type": "application/json"})
        h = stub_harness(m)
        with mock.patch.object(sa, "DELAY", 0):
            with self.assertRaises(sa.AbortRun) as ctx:
                sa.ws2_object_authz(h, self.cfg)
        self.assertEqual(ctx.exception.status, 403)

    def test_get_429_aborts_run_even_for_anon(self):
        """429 (rate limit) luon dung, ke ca o probe 'expected deny'."""
        m = dict(self.mapping)
        m[("GET", "anon", "/api/favorites")] = FakeResponse(
            b"{}", status=429, headers={"Content-Type": "application/json"})
        h = stub_harness(m)
        with mock.patch.object(sa, "DELAY", 0):
            with self.assertRaises(sa.AbortRun) as ctx:
                sa.ws2_object_authz(h, self.cfg)
        self.assertEqual(ctx.exception.status, 429)

    def test_expect_deny_403_does_not_abort(self):
        """403 o probe 'expected deny' la ket qua mong doi -> KHONG dung."""
        m = dict(self.mapping)
        m[("GET", "anon", "/api/reading-history")] = FakeResponse(
            b"{}", status=403, headers={"Content-Type": "application/json"})
        h = stub_harness(m, allow_mutate=True, mutate_authorized=True)
        with mock.patch.object(sa, "DELAY", 0):
            out = sa.ws2_object_authz(h, self.cfg)
        rec = out["write_phase"]["records"]["reading-history"]
        self.assertTrue(rec["anon_rejected"])

    def test_post_without_authorization_is_refused(self):
        """Regression D-3: moi write deu phai bi chan khi khong co quyen."""
        h = self._h(allow_mutate=False, mutate_authorized=False)
        with self.assertRaises(sa.WriteNotAuthorized):
            h.post("A", "/api/reading-history", json_body={})

    def test_post_with_allow_mutate_but_not_authorized_is_refused(self):
        h = self._h(allow_mutate=True, mutate_authorized=False)
        with self.assertRaises(sa.WriteNotAuthorized):
            h.post("A", "/api/reading-history", json_body={})

    def test_post_with_both_flags_is_allowed(self):
        h = self._h(allow_mutate=True, mutate_authorized=True)
        rec = h.post("A", "/api/reading-history", json_body={})
        self.assertEqual(rec["method"], "POST")
        self.assertEqual(len(h.writes), 1)

    def test_credentials_never_sent_to_unverified_host(self):
        """Host khong khop host da verify -> khong gui request nao."""
        h = self._h()
        with self.assertRaises(ValueError):
            h.get("A", "//evil.example.test/x")
        with self.assertRaises(ValueError):
            h.get("A", "https://evil.example.test/x")
        # Harness xac nhan host khac voi host da verify -> tu choi truoc khi gui
        with mock.patch.dict(os.environ, {k: "x" for k in sa.REQUIRED}, clear=True):
            h2 = sa.Harness("https://staging.example.test", False,
                            Path("recon/_unit_staging.json"),
                            verified_host="other.example.test")
            with self.assertRaises(ValueError):
                h2.get("A", "/truyen/x/doc/1.html")

    # ------------------------------------------------------------ plan
    def test_plan_writes_no_secrets_and_refuses_run(self):
        captured = {}

        def fake_write(self, text, encoding=None, **kw):
            captured["text"] = text
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(sa.Path, "write_text", new=fake_write), \
             mock.patch.object(sys, "argv",
                               ["ttm_staging_audit.py", "--plan", "--write-plan"]):
            rc = sa.main()
        self.assertEqual(rc, 3)
        self.assertNotIn("supersecret", captured["text"])
        self.assertIn("TTM_ALLOWED_STAGING_HOSTS", captured["text"])

    def test_plain_plan_does_not_touch_evidence_file(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(sys, "argv", ["ttm_staging_audit.py", "--plan"]):
            with mock.patch.object(sa.Path, "write_text") as w:
                sa.main()
        self.assertFalse(w.called)


if __name__ == "__main__":
    unittest.main()
