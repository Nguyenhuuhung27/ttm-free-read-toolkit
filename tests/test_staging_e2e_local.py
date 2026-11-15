"""End-to-end test cho `ttm_staging_audit.py --run` tren mock server LOCAL.

    python -m unittest tests.test_staging_e2e_local -v

Muc dich:
  `main()` -> Harness -> 5 workstream -> flush() -> recon/staging_audit.json
  la duong chay that ma nguoi dung se goi khi co staging that, nen phai kiem
  chay no voi mock server local (127.0.0.1) de bat loi truoc khi chay tren
  moi truong that.

Tinh chat:
  * Mock server chay tren 127.0.0.1:0 (ephemeral port) — khong dung domain
    nao ben ngoai, khong co production content.
  * Moi noi dung phai la SYNTHETIC (fixture trong tests/fixtures).
  * Khong co request nao ra ngoai mayy.
  * Khong ghi file nao vao repo (dung --out trong thu muc tam).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ttm_staging_audit as sa  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
FREE_HTML = (FIX / "free_chapter.html").read_text(encoding="utf-8")
LOCKED_HTML = (FIX / "locked_chapter.html").read_text(encoding="utf-8")
# Classifier yeu cau body > 200 ky tu de coi A la "that su co entitlement".
LONG_PAD = "SYNTHETIC-PADDING-" * 20
FREE_HTML_LONG = FREE_HTML.replace("Dong ba ket thuc.",
                                   "Dong ba ket thuc. " + LONG_PAD)

SLUG = "synthetic-story"
CHAPTER = "1"
CHAPTER_ID = "01SYNTHETIC0000000000000"
STORY_ID = "01SYNTHETICSTORY00000000"

COOKIE_A_VALUE = "synthetic-session-alpha-9f3c2b"
COOKIE_B_VALUE = "synthetic-session-beta-7a1d4e"

# A duoc entitlement (co audio), B khong (khong audio).
AUDIO_PAGE_A = ('<!DOCTYPE html><html><body><div class="prose">'
                'SYNTHETIC-TEST-BODY audio page for session A</div>'
                '<script>self.__next_f.push([1,'
                '"{\\"audioUrl\\":\\"https://cdn.synthetic.invalid/a.m4a\\"}"])'
                '</script></body></html>')

READING_RECORD = json.dumps(
    {"readingHistory": [{"storyId": STORY_ID, "chapterNumber": 1}]}).encode()
READING_EMPTY = json.dumps({"readingHistory": []}).encode()


def _who(headers) -> str:
    """A / B / anon theo cookie session gia (khong phai cookie that)."""
    ck = headers.get("Cookie", "")
    if ck == COOKIE_A_VALUE:
        return "A"
    if ck == COOKIE_B_VALUE:
        return "B"
    return "anon"


class Handler(BaseHTTPRequestHandler):
    """Chi phuc vu duong dan synthetic cua harness; tra 404 cho phan con lai."""

    def log_message(self, *_args):   # giu output test sach
        pass

    def _send(self, body: bytes, ctype: str, status: int = 200,
              extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store, max-age=0")
        self.send_header("cf-cache-status", "DYNAMIC")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        who = _who(self.headers)
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if path == "/api/reading-history":
            # A duoc tao record; B bi tu choi (403) -> phai la ket qua
            # mong doi, khong phai abort.
            if who == "A":
                return self._send(b'{"ok":true}', "application/json", status=201)
            return self._send(b'{"error":"forbidden"}', "application/json",
                              status=403)
        return self._send(b"not found", "text/plain", status=404)

    def do_GET(self):
        who = _who(self.headers)
        path = self.path.split("?")[0]
        html = "text/html; charset=utf-8"

        if path == f"/truyen/{SLUG}/doc/{CHAPTER}.html":
            body = (FREE_HTML_LONG if who == "A" else LOCKED_HTML).encode()
            return self._send(body, html)
        if path == f"/truyen/{SLUG}/nghe/{CHAPTER}.html":
            body = (AUDIO_PAGE_A if who == "A" else LOCKED_HTML).encode()
            return self._send(body, html)
        if path == "/api/reading-history":
            if who == "A":
                return self._send(READING_RECORD, "application/json")
            if who == "B":
                return self._send(READING_EMPTY, "application/json")
            return self._send(b'{"error":"unauthorized"}', "application/json",
                              status=401)
        if path in ("/api/favorites", "/api/notifications",
                    "/api/listening-history", "/api/user/audio-remaining"):
            return self._send(b'{"favorites":[]}', "application/json")
        if path == f"/api/chapters/{CHAPTER_ID}/comments":
            return self._send(b'{"comments":[]}', "application/json")
        if path == "/api/config":
            return self._send(b'{"featureFlags":{"synthetic":true}}',
                              "application/json")
        if path == "/sitemap.xml":
            return self._send(b'<?xml version="1.0"?><urlset/>',
                              "application/xml")
        if path.startswith(f"/truyen/{SLUG}/doc/{CHAPTER}"):
            # WS5 matcher probes: chap nhan moi, khong redirect -> gated=False
            return self._send(LOCKED_HTML.encode(), html)
        return self._send(b"not found", "text/plain", status=404)


class TestStagingEndToEndLocal(unittest.TestCase):
    """Chay --run day du tren 127.0.0.1, kiem tra output JSON."""

    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()

    def _env(self, mutate: bool = False) -> dict:
        env = {
            "TTM_STAGING_URL": f"http://127.0.0.1:{self.port}",
            "TTM_ALLOWED_STAGING_HOSTS": "127.0.0.1",
            "TTM_COOKIE_A": COOKIE_A_VALUE,
            "TTM_COOKIE_B": COOKIE_B_VALUE,
            "TTM_TEST_SLUG": SLUG,
            "TTM_TEST_CHAPTER": CHAPTER,
            "TTM_TEST_CHAPTER_ID": CHAPTER_ID,
            "TTM_TEST_STORY_ID": STORY_ID,
        }
        if mutate:
            env["TTM_MUTATE_AUTHORIZED"] = "1"
        return env

    def _run(self, out: Path, *, mutate: bool = False) -> int:
        argv = ["ttm_staging_audit.py", "--run", "--out", str(out)]
        if mutate:
            argv.append("--allow-mutate")
        with mock.patch.dict(os.environ, self._env(mutate), clear=True), \
             mock.patch.object(sa, "DELAY", 0), \
             mock.patch.object(sys, "argv", argv):
            return sa.main()

    def test_end_to_end_run_produces_complete_evidence(self):
        with TemporaryDirectory() as td:
            out = Path(td) / "staging_audit.json"
            rc = self._run(out)
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists(), "khong ghi ra file evidence")
            data = json.loads(out.read_text(encoding="utf-8"))

            # 1) Tat ca 5 workstream co mat va co verdict
            for key in ("ws1_session_isolation", "ws2_object_authz",
                        "ws3_cache_isolation", "ws4_audio_entitlement",
                        "ws5_matcher"):
                self.assertIn(key, data["sections"])
                self.assertIn("status", data["sections"][key])
            self.assertEqual(data["verdict"]["confirmed_vulnerabilities"], [])
            self.assertFalse(data["aborted"])

            # 2) Rows duoc ghi nhung KHONG co secret
            self.assertGreater(len(data["rows"]), 20)
            raw = out.read_text(encoding="utf-8")
            # Gia tri cookie session KHONG duoc xuat hien (chi duoc ghi 8 ky tu
            # hash trong prerequisites.sessions_fp).
            for secret in (COOKIE_A_VALUE, COOKIE_B_VALUE):
                self.assertNotIn(secret, raw)
            self.assertIn("TTM_COOKIE_A", raw)
            self.assertEqual(len(data["prerequisites"]["sessions_fp"]["A"]), 8)

            # 3) WS1: A co entitlement that, B khong nhan body cua A
            ws1 = data["sections"]["ws1_session_isolation"]
            self.assertTrue(ws1["A_entitled"])
            self.assertFalse(ws1["B_received_A_body"])
            self.assertEqual(ws1["props"]["B"]["content_state"],
                             "LOCKED_NO_PROTECTED_DATA")
            # Fingerprint NOI DUNG (khong phai hash toan response)
            self.assertIsNotNone(ws1["content_fingerprints"]["A"]["sha256"])
            self.assertIsNone(ws1["content_fingerprints"]["B"]["sha256"])
            # Marker synthetic chi xuat hien o noi dung synthetic
            self.assertTrue(ws1["rows"]["A"]["synthetic_marker_present"])
            self.assertFalse(ws1["rows"]["anon"]["synthetic_marker_present"])

            # 4) WS2: 6 object; mac dinh KHONG co write nao
            objs = data["sections"]["ws2_object_authz"]["objects"]
            self.assertEqual(len(objs), 6)
            self.assertIn("reading-history", objs)
            self.assertFalse(data["sections"]["ws2_object_authz"]
                             ["write_phase"]["executed"])
            self.assertEqual(data["writes"], [])
            self.assertFalse(data["write_authorized"])

            # 5) WS4: A co audio, B khong -> consistent
            ws4 = data["sections"]["ws4_audio_entitlement"]
            self.assertTrue(ws4["a_has_audio"])
            self.assertFalse(ws4["b_has_audio"])
            self.assertEqual(ws4["audio_state"], "OBSERVED_CONSISTENT")

            # 6) WS5: co fingerprint de gan build
            ws5 = data["sections"]["ws5_matcher"]
            self.assertEqual(len(ws5["probes"]), 9)
            self.assertIn("sitemap", ws5["fingerprint"])
            self.assertIn("config", ws5["fingerprint"])

    def test_end_to_end_mutate_phase_runs_only_when_authorized(self):
        """--allow-mutate + TTM_MUTATE_AUTHORIZED=1 -> phase 2 chay va ghi
        nhan write; khong co quyen thi phai khong co write nao."""
        with TemporaryDirectory() as td:
            out = Path(td) / "staging_audit.json"
            rc = self._run(out, mutate=True)
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            wp = data["sections"]["ws2_object_authz"]["write_phase"]
            self.assertTrue(wp["executed"])
            self.assertEqual(wp["records"]["reading-history"]["status"],
                             "OBSERVED_ISOLATED")
            self.assertEqual(len(data["writes"]), 2)
            self.assertTrue(data["write_authorized"])

    def test_end_to_end_mutate_is_refused_without_env_authorization(self):
        """Co --allow-mutate nhung thieu TTM_MUTATE_AUTHORIZED=1 -> exit 3,
        KHONG duoc gui request nao."""
        with TemporaryDirectory() as td:
            out = Path(td) / "staging_audit.json"
            argv = ["ttm_staging_audit.py", "--run", "--allow-mutate",
                    "--out", str(out)]
            boom = mock.Mock(side_effect=AssertionError("network called!"))
            with mock.patch.dict(os.environ, self._env(mutate=False), clear=True), \
                 mock.patch.object(sa.requests.Session, "get", boom), \
                 mock.patch.object(sa.requests.Session, "post", boom), \
                 mock.patch.object(sys, "argv", argv):
                rc = sa.main()
            self.assertEqual(rc, 3)
            self.assertFalse(boom.called)
            self.assertFalse(out.exists())

    def test_run_output_never_enters_repo(self):
        """Ghi evidence ra thu muc tam, khong lam dirty repo."""
        with TemporaryDirectory() as td:
            out = Path(td) / "staging_audit.json"
            rc = self._run(out)
            self.assertEqual(rc, 0)
            self.assertFalse((ROOT / "recon" / "staging_audit.json").exists(),
                             "harness khong duoc ghi evidence vao repo khi "
                             "--out chi dinh thu muc khac")


if __name__ == "__main__":
    unittest.main()
