"""Offline regression tests — khong can network, khong can credentials.

Chay:
    python -m unittest discover -s tests -v

Cac test nay chi dung synthetic fixtures trong tests/fixtures/ va evidence JSON
da co san trong recon/. Khong goi requests, khong doc file cau hinh/bi mat,
khong dung noi dung chuong that.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(ROOT))

import audit_classify as ac  # noqa: E402
from ttm_entitlement_audit import inspect, resolve_content  # noqa: E402
from ttm_recon import (chapter_body, flight_stream, iter_chunks,  # noqa: E402
                       parse_chapter_props, parse_chapters, strip_rsc_prefix)


def load(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


class TestRSCParser(unittest.TestCase):
    def test_flight_stream_decodes_json_string_literal(self):
        s = flight_stream(load("free_chapter.html"))
        self.assertIn("SYNTHETIC-TEST-BODY", s)
        self.assertIn('"locked":false', s)

    def test_parse_chapter_props_free(self):
        s = flight_stream(load("free_chapter.html"))
        p = parse_chapter_props(s)
        self.assertEqual(p.get("locked"), False)
        self.assertEqual(p.get("content"), "$1b")
        self.assertEqual(p.get("chapterId"), "01SYNTHETICFREE0000000000")

    def test_parse_chapter_props_locked(self):
        s = flight_stream(load("locked_chapter.html"))
        p = parse_chapter_props(s)
        self.assertEqual(p.get("locked"), True)
        self.assertEqual(p.get("content"), "")

    def test_parse_chapters_toc(self):
        ch = parse_chapters(flight_stream(load("toc.html")))
        self.assertEqual(len(ch), 3)
        self.assertEqual([c["chapterNumber"] for c in ch], [1, 2, 3])
        self.assertEqual([c["isLocked"] for c in ch], [False, True, True])

    def test_parse_chapters_ignores_stream_without_toc(self):
        self.assertEqual(parse_chapters("1:HL[\"x\",\"font\",{}]"), [])

    def test_iter_chunks_keeps_real_newlines_in_body(self):
        s = flight_stream(load("free_chapter.html"))
        chunks = dict(iter_chunks(s))
        self.assertIn("1b", chunks)
        self.assertIn("\r\n", chunks["1b"], "newline that trong body phai duoc giu")

    def test_strip_rsc_prefix(self):
        self.assertEqual(strip_rsc_prefix("T16050,abc"), "abc")
        self.assertEqual(strip_rsc_prefix("Taba4,abc"), "abc")
        self.assertEqual(strip_rsc_prefix("no-prefix"), "no-prefix")

    def test_chapter_body_ignores_module_reference(self):
        s = flight_stream(load("locked_chapter.html"))
        self.assertIn("1b", dict(iter_chunks(s)))
        self.assertEqual(chapter_body(s), "", "chunk I[...] khong phai body")

    def test_chapter_body_returns_free_body(self):
        s = flight_stream(load("free_chapter.html"))
        self.assertTrue(chapter_body(s).startswith("T16050,SYNTHETIC-TEST-BODY"))

    def test_utf8_vietnamese_preserved(self):
        s = flight_stream(load("free_chapter.html"))
        body = strip_rsc_prefix(chapter_body(s))
        self.assertIn("Tiểu Thuyết Mạng", body)
        self.assertNotIn("Ã", body, "mojibake ISO-8859-1 khong duoc phep")


class TestInspectChannels(unittest.TestCase):
    def test_free_html(self):
        i = inspect(load("free_chapter.html"), "text/html; charset=utf-8")
        self.assertEqual(i["locked"], False)
        self.assertEqual(i["content_field"], "$1b")
        self.assertGreater(i["body_chars"], 100)
        self.assertGreater(i["dom_prose_chars"], 0)
        self.assertFalse(i["has_audio_url"])

    def test_locked_html_has_no_protected_data(self):
        i = inspect(load("locked_chapter.html"), "text/html; charset=utf-8")
        self.assertEqual(i["locked"], True)
        self.assertEqual(i["content_field"], "")
        self.assertEqual(i["body_chars"], 0)
        self.assertEqual(i["dom_prose_chars"], 0)
        self.assertFalse(i["has_audio_url"])
        self.assertEqual(ac.content_state(locked=i["locked"],
                                          body_chars=i["body_chars"],
                                          has_audio_url=i["has_audio_url"]),
                         "LOCKED_NO_PROTECTED_DATA")

    def test_free_rsc_uses_content_reference_not_hardcoded_chunk(self):
        raw = load("free_chapter.rsc")
        p = parse_chapter_props(raw)
        self.assertEqual(p.get("content"), "$15")
        n, excerpt = resolve_content(raw, p.get("content"))
        self.assertGreater(n, 100)
        self.assertIn("SYNTHETIC-TEST-BODY", excerpt)

    def test_locked_rsc_has_no_body(self):
        raw = load("locked_chapter.rsc")
        i = inspect(raw, "text/x-component")
        self.assertEqual(i["locked"], True)
        self.assertEqual(i["body_chars"], 0)
        self.assertEqual(i["dom_prose_chars"], 0, "RSC khong co DOM de do")

    def test_html_and_rsc_free_bodies_are_identical_length(self):
        a = inspect(load("free_chapter.html"), "text/html")["body_chars"]
        b = inspect(load("free_chapter.rsc"), "text/x-component")["body_chars"]
        self.assertEqual(a, b, "HTML va RSC phai cung do dai body")


class TestClassificationRules(unittest.TestCase):
    def test_http_status_is_not_an_input(self):
        # Bao ve brief rule 6: ham phan loai KHONG nhan status code.
        import inspect as pyinspect
        params = list(pyinspect.signature(ac.content_state).parameters)
        self.assertNotIn("status", params)
        self.assertNotIn("status_code", params)

    def test_locked_with_body_needs_review_not_auto_exploit(self):
        self.assertEqual(ac.content_state(locked=True, body_chars=9999),
                         "LOCKED_WITH_DATA_NEEDS_REVIEW")

    def test_free_with_body(self):
        self.assertEqual(ac.content_state(locked=False, body_chars=100),
                         "FREE_CONTENT_PRESENT")

    def test_missing_locked_flag_is_unknown(self):
        self.assertEqual(ac.content_state(locked=None, body_chars=0), ac.UNKNOWN)

    def test_classify_requires_reproduction_for_observed(self):
        self.assertEqual(ac.classify("x", evidence_refs=["a"], reproduced=False)["status"],
                         ac.INFERRED)
        self.assertEqual(ac.classify("x", evidence_refs=["a"], reproduced=True)["status"],
                         ac.OBSERVED)
        self.assertEqual(ac.classify("x", evidence_refs=[], reproduced=False)["status"],
                         ac.UNKNOWN)

    def test_missing_prerequisite_forces_unknown(self):
        r = ac.classify("cache leak", evidence_refs=["recon/x.json"], reproduced=True,
                        prerequisite_missing="2 authorized test accounts")
        self.assertEqual(r["status"], ac.UNKNOWN)

    def test_redact(self):
        out = ac.redact("__Host-next-auth.csrf-token=abc123def456; Path=/; Bearer xyz1234567890")
        self.assertNotIn("abc123def456", out)
        self.assertNotIn("xyz1234567890", out)
        self.assertIn("<redacted", out)


class TestCacheIsolationClassifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(load("sessions_fixture.json"))

    def test_no_sessions_is_unknown(self):
        self.assertEqual(ac.cache_isolation_state(session_rows=self.data["no_sessions"],
                                                  cache_hit_seen=False),
                         "UNKNOWN_NO_AUTHORIZED_SESSIONS")

    def test_a_not_entitled_is_unknown(self):
        self.assertEqual(ac.cache_isolation_state(session_rows=self.data["a_not_entitled"],
                                                  cache_hit_seen=False),
                         "UNKNOWN_A_NOT_ENTITLED")

    def test_isolated(self):
        self.assertEqual(ac.cache_isolation_state(session_rows=self.data["isolated"],
                                                  cache_hit_seen=False),
                         "OBSERVED_ISOLATED")

    def test_leak_detection(self):
        self.assertEqual(ac.cache_isolation_state(session_rows=self.data["leak"],
                                                  cache_hit_seen=True),
                         "OBSERVED_CROSS_SESSION_LEAK")

    def test_vary_header_alone_never_proves_leak(self):
        # Khong co session rows -> UNKNOWN du header co thieu Vary: Cookie.
        headers = json.loads(load("headers_fixture.json"))
        self.assertNotIn("Cookie", headers["user_scoped_ok"]["Vary"])
        self.assertEqual(ac.cache_isolation_state(session_rows=[], cache_hit_seen=False),
                         "UNKNOWN_NO_AUTHORIZED_SESSIONS")


class TestEvidenceIntegrity(unittest.TestCase):
    """Kiem tra cac claim cua report cu con dung voi evidence JSON hien tai."""

    @classmethod
    def setUpClass(cls):
        cls.ctrl = json.loads((ROOT / "recon/control_audit.json").read_text(encoding="utf-8"))
        cls.sweep = json.loads((ROOT / "recon/entitlement_sweep.json").read_text(encoding="utf-8"))
        cls.passive = json.loads((ROOT / "recon/passive_check.json").read_text(encoding="utf-8"))

    def test_gate_dot_suffix_probe_has_10_rows(self):
        rows = self.ctrl["sections"]["gate"]["dot_suffix_probe"]
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(1 for x in rows if x["gated"]), 1)
        # `.html/x` la 404 (route khong ton tai), van KHONG bi gate; cac
        # duoi con lai bypass thanh 200. Ca 9 case deu di qua gate.
        self.assertEqual(sum(1 for x in rows if x["status"] == 200), 8)
        self.assertEqual(sum(1 for x in rows if x["status"] == 404), 1)
        self.assertTrue(all(not x["gated"] for x in rows if x["suffix"] != "(none)"))

    def test_locked_chapter_has_no_body_in_evidence(self):
        c = self.ctrl["sections"]["content"]["chapters"]["locked"]
        self.assertEqual(c["rsc_body_chars"], 0)
        self.assertEqual(c["dom_selector_chars"]["div.prose, .prose"], 0)
        self.assertFalse(c["contains_audio_url"])

    def test_apis_have_no_content_field(self):
        apis = self.ctrl["sections"]["content"]["api"]
        self.assertEqual(len(apis), 11)
        self.assertFalse(any(x["has_content_field"] for x in apis))
        self.assertFalse(any(x["has_audio_url"] for x in apis))

    def test_19_entitlement_probes_all_locked(self):
        s = self.sweep["sections"]["server_authorization"]
        rows = s["client_params"] + s["privilege_headers"] + s["cookie_variants"]
        self.assertEqual(len(rows), 19)
        self.assertTrue(all(x["body_chars"] == 0 for x in rows))
        self.assertTrue(all(x["content"] == "" for x in rows))

    def test_sweep_51_chapters_all_consistent(self):
        rows = self.sweep["sections"]["content_delivery"]["toc_consistency"]
        self.assertEqual(len(rows), 51)
        self.assertTrue(all(x["consistent"] for x in rows))
        self.assertEqual(sum(1 for x in rows if x["toc_isLocked"]), 48)
        self.assertTrue(all(x["body_chars"] == 0 for x in rows if x["toc_isLocked"]))

    def test_no_real_sessions_recorded(self):
        cache = self.sweep["sections"]["cache"]
        self.assertIsNone(cache.get("sessions"))
        self.assertIn("sessions_note", cache)
        self.assertEqual(ac.cache_isolation_state(session_rows=cache.get("sessions") or [],
                                                  cache_hit_seen=False),
                         "UNKNOWN_NO_AUTHORIZED_SESSIONS")

    def test_cache_no_hit_in_evidence(self):
        for x in self.sweep["sections"]["cache"]["repeat"]:
            self.assertEqual(x["cf"], "DYNAMIC")
            self.assertIsNone(x["age"])
            self.assertIsNone(x["etag"])

    def test_config_conflicting_cache_control(self):
        rows = self.ctrl["sections"]["config"]["cache"]
        cfg = next(x for x in rows if x["path"] == "/api/config")
        self.assertTrue(cfg["conflicting_public_private"])
        self.assertFalse(cfg["vary_has_cookie"])

    def test_f2_error_responses_hide_sensitive_patterns(self):
        cases = self.ctrl["sections"]["errors"]["cases"]
        self.assertEqual(len(cases), 8)
        bad = ("php_version", "framework_version", "internal_fs_path",
               "stack_trace", "secret_like", "env_var", "sql")
        for c in cases:
            for k in bad:
                self.assertFalse(c["patterns_found"].get(k),
                                 f"{c['label']} unexpectedly matched {k}")

    def test_passive_fingerprint_present(self):
        self.assertEqual(self.passive["deployment"]["gate_flag_value"], "1")
        self.assertEqual(len(self.passive["deployment"]["sitemap_lastmod"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
