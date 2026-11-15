#!/usr/bin/env python3
"""Fail-closed A/B staging audit harness cho 5 uu tien danh gia.

    python ttm_staging_audit.py --plan          # KHONG network, in ke hoach + thieu gi
    python ttm_staging_audit.py --run           # CHI chay khi du prerequisite

NGUYEN TAC (fail-closed):
  * Refuse to run neu thieu bat ky prerequisite nao. Khong "chay thu" voi production.
  * Host staging phai khai bao EXACT trong TTM_ALLOWED_STAGING_HOSTS, hoac la
    localhost/127.0.0.1 (dung cho dev + test end-to-end local). KHONG dung
    substring matching: "evil-staging.attacker.com" chua "staging" nen
    substring se mo cong. Moi host deu la exact match.
  * Session co cookie CHI duoc tao sau khi host da duoc verify. Moi request
    lai kiem tra host truoc khi gui -> khong gui credential toi host chua
    verify du dui mot byte nao.
  * Chi GET (va OPTIONS harmless). Moi WRITE chi khi co --allow-mutate VA
    TTM_MUTATE_AUTHORIZED=1; mac dinh KHONG BAO GIO mutate.
  * Chi dung test chapter SYNTHETIC do owner cung cap (TTM_TEST_SLUG /
    TTM_TEST_CHAPTER / TTM_TEST_CHAPTER_ID / TTM_TEST_STORY_ID). Khong doc
    noi dung chuong that, khong enumerate ID nguoi khac.
  * Khong log cookie/token/gia tri body. Chi log status, header whitelist,
    SHA-256, va co mat cua marker synthetic.
  * DUNG NGAY khi gap 403/429 (tru 403 lai la probe "expected deny").
  * 1 luong, nghi >=2s/request.
  * Moi ket luan di qua audit_classify (khong nhan HTTP status lam input).

ENV bat buoc:
    TTM_STAGING_URL          https://...  (phai la staging, khong phai production)
    TTM_ALLOWED_STAGING_HOSTS  danh sach host staging, tach bang dau phay
    TTM_COOKIE_A             session cua A (co entitlement toi test chapter)
    TTM_COOKIE_B             session cua B (khong co entitlement)
    TTM_TEST_SLUG            slug cua truyen synthetic
    TTM_TEST_CHAPTER         so chuong synthetic
    TTM_TEST_CHAPTER_ID      chapterId synthetic
    TTM_TEST_STORY_ID        storyId synthetic

ENV tuy chon:
    TTM_SCOPE_REF            ma tham chieu uy quyen (chi ghi vao evidence, khong kiem tra)
    TTM_MUTATE_AUTHORIZED    1 neu scope cho phep POST tao test records
    TTM_AUDIO_TEST_URL       URL audio synthetic (neu co)

Exit code: 0 = ok, 3 = prerequisite chua san sang, 4 = bi dung do 403/429.

Output: recon/staging_audit.json (chi metadata + hash, khong co noi dung)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

from audit_classify import (INFERRED, OBSERVED, UNKNOWN, audio_entitlement_state,
                            audio_signals, cache_isolation_state, classify,
                            content_fingerprint, content_state, normalize_content,
                            object_authz_state, record_fingerprint, redact)

DELAY = 2.0
TIMEOUT = 25
PRODUCTION_HOSTS = {"tieuthuyetmang.com", "www.tieuthuyetmang.com",
                    "img.tieuthuyetmang.com", "audio.tieuthuyetmang.com"}
# Host local duoc phep mac dinh: dung cho dev noi bo va test end-to-end local.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
SYNTHETIC_MARKER = "SYNTHETIC-TEST-BODY"
HEADER_WHITELIST = ("Content-Type", "Cache-Control", "Vary", "Age", "ETag",
                    "Last-Modified", "cf-cache-status", "Location", "Server",
                    "X-Powered-By", "Access-Control-Allow-Origin",
                    "Access-Control-Allow-Credentials")

REQUIRED = ("TTM_STAGING_URL", "TTM_ALLOWED_STAGING_HOSTS", "TTM_COOKIE_A",
            "TTM_COOKIE_B", "TTM_TEST_SLUG", "TTM_TEST_CHAPTER",
            "TTM_TEST_CHAPTER_ID", "TTM_TEST_STORY_ID")

EXIT_OK = 0
EXIT_NOT_READY = 3
EXIT_ABORTED = 4


class AbortRun(Exception):
    """Gap 403/429 -> dung NGAY, khong giu tiep, khong gui them request."""

    def __init__(self, status: int, path: str, who: str):
        super().__init__(f"HTTP {status} tai {path} (session {who})")
        self.status = status
        self.path = path
        self.who = who


class WriteNotAuthorized(Exception):
    """Yeu cau write nhung khong co --allow-mutate + TTM_MUTATE_AUTHORIZED=1."""


# ------------------------------------------------------------------ gating
def env_state() -> dict:
    """Tra ve do DAI cua tung env, KHONG BAO GIO tra gia tri."""
    return {k: len(os.environ.get(k, "")) for k in REQUIRED}


def allowed_hosts() -> set[str]:
    """Danh sach host staging duoc phep — exact match, KHONG substring."""
    raw = os.environ.get("TTM_ALLOWED_STAGING_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def staging_host_ok(url: str, allow: set[str]) -> tuple[bool, str]:
    """Kiem tra host staging theo exact-match allowlist.

    Quy tac: host local (localhost/127.0.0.1/::1) duoc phep luon; host khac
    phai xuat hien CHINH XAC trong allowlist. Khong su dung substring.
    """
    if not url:
        return False, "TTM_STAGING_URL chua set"
    try:
        u = urlparse(url)
    except ValueError as exc:
        return False, f"URL khong parse duoc: {exc}"
    if u.scheme not in ("http", "https"):
        return False, "scheme phai la http/https"
    host = (u.hostname or "").lower()
    if not host:
        return False, "thieu hostname"
    if host in PRODUCTION_HOSTS or host.endswith(".tieuthuyetmang.com"):
        return False, f"TU CHOI: host production '{host}' khong duoc phep"
    if host in LOCAL_HOSTS:
        if u.scheme != "https" and host not in ("localhost", "127.0.0.1"):
            return False, "staging tu xa bat buoc phai https"
        return True, host
    if host not in allow:
        return False, (f"TU CHOI: host '{host}' khong co trong allowlist "
                       "TTM_ALLOWED_STAGING_HOSTS (exact match)")
    if u.scheme != "https":
        return False, "staging tu xa bat buoc phai https"
    return True, host


def prerequisites() -> dict:
    e = env_state()
    missing = [k for k, n in e.items() if n == 0]
    base = os.environ.get("TTM_STAGING_URL", "")
    allow = allowed_hosts()
    host_ok, host_msg = staging_host_ok(base, allow)
    a, b = os.environ.get("TTM_COOKIE_A", ""), os.environ.get("TTM_COOKIE_B", "")
    sessions_ok = bool(a and b and a != b)
    return {
        "env_lengths": e, "missing": missing,
        "allowed_staging_hosts": sorted(allow),
        "staging_host_ok": host_ok, "staging_host_message": host_msg,
        "sessions_independent": sessions_ok,
        "sessions_fp": {"A": fp(a), "B": fp(b)} if a and b else {},
        "scope_ref": os.environ.get("TTM_SCOPE_REF", "")[:80],
        "mutate_authorized": os.environ.get("TTM_MUTATE_AUTHORIZED") == "1",
        "ready": (not missing and host_ok and sessions_ok),
    }


def fp(cookie: str) -> str:
    return hashlib.sha256(cookie.encode()).hexdigest()[:8] if cookie else "-"


def die(pr: dict) -> int:
    print("PREREQUISITES NOT MET — khong co request nao duoc gui.", file=sys.stderr)
    for k in pr["missing"]:
        print(f"  missing: {k}", file=sys.stderr)
    print(f"  staging: {pr['staging_host_message']}", file=sys.stderr)
    if not pr["sessions_independent"]:
        print("  sessions: TTM_COOKIE_A/B phai ton tai va KHAC NHAU", file=sys.stderr)
    print("  -> Chay lai khi co staging + 2 tai khoan duoc uy quyen + test chapter synthetic.",
          file=sys.stderr)
    return EXIT_NOT_READY


# ------------------------------------------------------------------- request
class Harness:
    def __init__(self, base: str, allow_mutate: bool, out: Path,
                 mutate_authorized: bool = False, verified_host: str | None = None):
        self.base = base.rstrip("/")
        self.allow_mutate = bool(allow_mutate)
        self.mutate_authorized = bool(mutate_authorized)
        self.out = out
        self.verified_host = (verified_host or "").lower()
        # Session co cookie CHI duoc tao sau khi host da duoc verify.
        self.sessions = {
            "A": self._session(os.environ["TTM_COOKIE_A"]),
            "B": self._session(os.environ["TTM_COOKIE_B"]),
            "anon": self._session(None),
        }
        self.rows: list[dict] = []
        self.writes: list[dict] = []
        self._texts: dict[int, str] = {}   # in-memory only, KHONG ghi ra file
        self._raw: dict[int, bytes] = {}   # in-memory only, KHONG ghi ra file
        self.test_id = f"STG-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    @staticmethod
    def _session(cookie: str | None) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": "ttm-staging-audit/1.0 (authorized test)",
                          "Accept": "*/*"})
        if cookie:
            s.headers["Cookie"] = cookie
        return s

    @property
    def mutations_allowed(self) -> bool:
        """True CHI KHI ca hai co: --allow-mutate va TTM_MUTATE_AUTHORIZED=1."""
        return self.allow_mutate and self.mutate_authorized

    def _url(self, path: str) -> str:
        """Chuyen path thanh URL sau khi kiem tra host + hinh dang path."""
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError(f"path khong hop le: {path!r}")
        url = self.base + path
        host = (urlparse(url).hostname or "").lower()
        if host != self.verified_host:
            raise ValueError(f"host khong khop host da verify: {host!r}")
        return url

    def _record(self, who: str, method: str, path: str, r, body: bytes) -> dict:
        rec = {
            "test_id": self.test_id, "who": who, "method": method, "path": path,
            "status": r.status_code,
            "bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest()[:16],
            "synthetic_marker_present": SYNTHETIC_MARKER.encode() in body,
            "headers": {k: redact(str(r.headers.get(k)))
                        for k in HEADER_WHITELIST if r.headers.get(k) is not None},
            "cookie_logged": False,
        }
        self.rows.append(rec)
        self._texts[len(self.rows) - 1] = body.decode("utf-8", errors="replace")
        self._raw[len(self.rows) - 1] = body
        return rec

    def _check_abort(self, rec: dict, *, expect_deny: bool) -> None:
        """Dung NGAY khi gap 403/429.

        403 lai la probe "expected deny" (anon bi tu choi) -> ghi nhan, KHONG
        dung. 429 (rate limit) luon dung, ke ca khi la expected deny.
        """
        status = rec["status"]
        if status == 429:
            raise AbortRun(429, rec["path"], rec["who"])
        if status == 403 and not expect_deny:
            raise AbortRun(403, rec["path"], rec["who"])

    def get(self, who: str, path: str, *, extra: dict | None = None,
            tag: str = "", expect_deny: bool = False) -> dict:
        url = self._url(path)
        r = self.sessions[who].get(url, headers=extra or {}, timeout=TIMEOUT,
                                   allow_redirects=False)
        time.sleep(DELAY)
        rec = self._record(who, "GET", path, r, r.content)
        rec["tag"] = tag
        self._check_abort(rec, expect_deny=expect_deny)
        return rec

    def post(self, who: str, path: str, *, json_body: dict | None = None,
             tag: str = "", expect_deny: bool = False) -> dict:
        """WRITE. Chi chay khi --allow-mutate VA TTM_MUTATE_AUTHORIZED=1."""
        if not self.mutations_allowed:
            raise WriteNotAuthorized(
                "WRITE bi chan: can --allow-mutate va TTM_MUTATE_AUTHORIZED=1")
        url = self._url(path)
        r = self.sessions[who].post(url, json=json_body, timeout=TIMEOUT,
                                    allow_redirects=False)
        time.sleep(DELAY)
        rec = self._record(who, "POST", path, r, r.content)
        rec["tag"] = tag
        self.writes.append({"who": who, "path": path, "status": r.status_code,
                            "tag": tag, "write_authorized": True})
        self._check_abort(rec, expect_deny=expect_deny)
        return rec

    def text_of(self, rec: dict) -> str:
        """Text raw cua response (in-memory). KHONG ghi ra evidence file."""
        for idx in range(len(self.rows) - 1, -1, -1):
            if self.rows[idx] is rec:
                return self._texts.get(idx, "")
        return ""

    def raw_of(self, rec: dict) -> bytes:
        for idx in range(len(self.rows) - 1, -1, -1):
            if self.rows[idx] is rec:
                return self._raw.get(idx, b"")
        return b""

    def record_fp(self, rec: dict) -> dict:
        """Fingerprint object record (hash + so luong), KHONG luu noi dung."""
        return record_fingerprint(self.raw_of(rec))

    @staticmethod
    def props(rec: dict, text: str) -> dict:
        """Parse entitlement state tu RSC payload (khong luu text ra file)."""
        from ttm_entitlement_audit import inspect
        ctype = rec["headers"].get("Content-Type") or "text/html"
        i = inspect(text, ctype)
        return {"locked": i["locked"], "content_field": i["content_field"],
                "body_chars": i["body_chars"], "dom_prose_chars": i["dom_prose_chars"],
                "has_audio_url": i["has_audio_url"],
                "content_state": content_state(locked=i["locked"],
                                               body_chars=i["body_chars"],
                                               has_audio_url=i["has_audio_url"])}

    def content_fp(self, rec: dict) -> dict:
        """Fingerprint CHI noi dung chuong duoc bao ve (doc lap metadata dong).

        Raw response khong bao gio ghi ra evidence file.
        """
        from ttm_recon import chapter_body, flight_stream, iter_chunks, strip_rsc_prefix
        from ttm_entitlement_audit import parse_chapter_props
        text = self.text_of(rec)
        ctype = rec["headers"].get("Content-Type") or "text/html"
        is_rsc = "x-component" in (ctype or "")
        stream = text if is_rsc else flight_stream(text)
        props = parse_chapter_props(stream)
        body = ""
        ref = props.get("content")
        if isinstance(ref, str) and ref.startswith("$"):
            cid = ref[1:]
            for k, payload in iter_chunks(stream):
                if k == cid:
                    body = strip_rsc_prefix(payload)
                    break
        if not body:
            body = strip_rsc_prefix(chapter_body(stream))
        fp = content_fingerprint(body)
        fp["locked"] = props.get("locked")
        fp["synthetic_marker_present"] = SYNTHETIC_MARKER in body
        return fp

    def flush(self, payload: dict) -> None:
        payload["test_id"] = self.test_id
        payload["at"] = datetime.now(timezone.utc).isoformat()
        payload["base_host"] = urlparse(self.base).hostname
        payload["rows"] = self.rows
        payload["writes"] = self.writes
        payload["write_authorized"] = self.mutations_allowed
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                            encoding="utf-8")


# ------------------------------------------------------------- 5 workstreams
def ws1_session_isolation(h: Harness, cfg: dict) -> dict:
    """Priority 1: A nhan dung cai A duoc phep; B khong nhan cua A.

    So sanh FINGERPRINT NOI DUNG (khong phai hash toan response) de loai b
    metadata dong (timestamp, request id) gay nhieu.
    """
    p = f"/truyen/{cfg['slug']}/doc/{cfg['chapter']}.html"
    rows, props, cfp = {}, {}, {}
    for w in ("A", "B", "anon"):
        rec = h.get(w, p, tag="ws1/chapter", expect_deny=(w == "anon"))
        rows[w] = rec
        props[w] = h.props(rec, h.text_of(rec))
        cfp[w] = h.content_fp(rec)
    a, b = props["A"], props["B"]
    a_entitled = a["locked"] is False and a["body_chars"] > 200
    b_saw_a = bool(a_entitled
                   and cfp["B"]["sha256"] and cfp["B"]["sha256"] == cfp["A"]["sha256"])
    return {
        "path": p, "rows": rows, "props": props, "content_fingerprints": cfp,
        "A_entitled": a_entitled,
        "B_received_A_body": b_saw_a,
        "status": (UNKNOWN if not a_entitled else
                   OBSERVED if not b_saw_a else "OBSERVED_NEEDS_REVIEW"),
        "classifier": cache_isolation_state(
            session_rows=[{"label": "A", "locked": a["locked"],
                           "body_chars": a["body_chars"],
                           "content_sha": cfp["A"]["sha256"]},
                          {"label": "B", "locked": b["locked"],
                           "body_chars": b["body_chars"],
                           "content_sha": cfp["B"]["sha256"]}],
            cache_hit_seen=False),
        "note": "Entitlement doc tu RSC props, KHONG tu HTTP status. "
                "B_received_A_body so sanh fingerprint NOI DUNG, khong so "
                "hash toan response (metadata dong lam sai). Chi co y nghia "
                "khi A_entitled=true.",
    }


# --- WS2: object-level authorization -------------------------------------
WS2_OBJECTS = (
    ("/api/reading-history", "reading-history"),
    ("/api/favorites", "favorites"),
    ("/api/notifications", "notifications"),
    ("/api/listening-history", "listening-history"),
    ("/api/chapters/{chapter_id}/comments", "comments"),
    ("/api/user/audio-remaining", "audio-remaining"),
)


def ws2_object_authz(h: Harness, cfg: dict) -> dict:
    """Priority 2: object-level authorization tren 6 object.

    Phase 1 (luon chay): baseline chi GET, so sanh A/B/anon.
    Phase 2 (CHI khi --allow-mutate + TTM_MUTATE_AUTHORIZED=1): tao record
    synthetic thuoc A roi kiem tra B co doc/sua duoc record do khong.
    """
    summary = {}
    for path_tpl, name in WS2_OBJECTS:
        path = path_tpl.format(chapter_id=cfg["chapter_id"])
        # Anonymous bi tu choi tren endpoint yeu cau dang nhap la KET QUA
        # MONG DOI -> khong duoc coi la abort. Session A/B bi chan 403 moi
        # la dau hieu server dang chan ta -> dung ngay.
        recs = {w: h.get(w, path, tag=f"ws2/{name}", expect_deny=(w == "anon"))
                for w in ("A", "B", "anon")}
        a_hash, b_hash = recs["A"]["body_sha256"], recs["B"]["body_sha256"]
        anon_hash = recs["anon"]["body_sha256"]
        a_has_own_data = a_hash != anon_hash
        b_got_a_data = b_hash == a_hash and a_has_own_data
        summary[name] = {
            "rows": recs, "a_bytes": recs["A"]["bytes"], "b_bytes": recs["B"]["bytes"],
            "a_equals_anon": not a_has_own_data,
            "b_equals_a": b_hash == a_hash,
            "a_has_session_specific_data": a_has_own_data,
            "needs_review": b_got_a_data,
            "status": ("OBSERVED_NEEDS_REVIEW" if b_got_a_data else
                       "OBSERVED_NO_CROSS_SESSION_DATA" if a_has_own_data else
                       "UNKNOWN_NO_SESSION_SPECIFIC_DATA"),
        }

    write_phase = {"executed": False, "status": UNKNOWN,
                   "reason": "Chua co --allow-mutate + TTM_MUTATE_AUTHORIZED=1 -> "
                             "khong tao record synthetic nao.",
                   "records": {}}
    if h.mutations_allowed:
        write_phase = _ws2_synthetic_workflow(h, cfg)

    return {"objects": summary, "write_phase": write_phase, "status": UNKNOWN,
            "note": "Khong ket luan IDOR tu hash bang nhau (ca hai deu rong). "
                    "Phase 2 can --allow-mutate + TTM_MUTATE_AUTHORIZED=1 de tao "
                    "record synthetic thuoc A. Khong enumerate ID, khong doc du "
                    "Lieu user khac."}


def _ws2_synthetic_workflow(h: Harness, cfg: dict) -> dict:
    """Tao record synthetic thuoc A va kiem tra quyen so huu.

    Chi dung ID synthetic tu env. Moi write deu di qua Harness.post() =>
    tu choi neu khong co --allow-mutate + TTM_MUTATE_AUTHORIZED=1.
    """
    rh = "/api/reading-history"
    body = {"storyId": cfg["story_id"], "chapterId": cfg["chapter_id"]}
    records = {}

    # 1) A tao record synthetic
    post_a = h.post("A", rh, json_body=body, tag="ws2/write/reading-history-A")
    a_view = h.get("A", rh, tag="ws2/read/reading-history-A")
    a_fp1 = h.record_fp(a_view)
    record_created = bool(200 <= post_a["status"] < 300 and a_fp1["count"])

    # 2) B co doc duoc record cua A?
    b_view = h.get("B", rh, tag="ws2/read/reading-history-B")
    b_fp = h.record_fp(b_view)
    b_can_read = bool(record_created and b_fp["count"] == a_fp1["count"]
                      and b_fp["sha256"] == a_fp1["sha256"])

    # 3) Anonymous co bi tu choi?
    anon_view = h.get("anon", rh, tag="ws2/read/reading-history-anon",
                      expect_deny=True)
    anon_fp = h.record_fp(anon_view)
    anon_rejected = bool(anon_view["status"] in (401, 403)
                         or not anon_fp["count"])

    # 4) B co sua duoc record cua A? (thu ghi de bang key synthetic)
    #    403/401 o day la KET QUA MONG DOI (B phai bi tu choi) -> khong abort.
    post_b = h.post("B", rh, json_body=body, tag="ws2/write/reading-history-B",
                     expect_deny=True)
    b_write_accepted = bool(200 <= post_b["status"] < 300)
    a_view2 = h.get("A", rh, tag="ws2/read/reading-history-A-after-B")
    a_fp2 = h.record_fp(a_view2)
    a_record_unchanged = bool(a_fp2["sha256"] == a_fp1["sha256"])

    records["reading-history"] = {
        "write_status_A": post_a["status"],
        "write_status_B": post_b["status"],
        "a_entry_count": a_fp1["count"],
        "a_record_sha256": a_fp1["sha256"],
        "a_record_sha256_after_B_write": a_fp2["sha256"],
        "b_entry_count": b_fp["count"],
        "anon_entry_count": anon_fp["count"],
        "anon_status": anon_view["status"],
        "record_created": record_created,
        "a_can_read": bool(a_fp1["count"]),
        "b_can_read": b_can_read,
        "anon_rejected": anon_rejected,
        "b_write_accepted": b_write_accepted,
        "a_record_unchanged": a_record_unchanged,
        "status": object_authz_state(
            record_created=record_created,
            a_can_read=bool(a_fp1["count"]),
            b_can_read=b_can_read,
            anon_rejected=anon_rejected,
            b_write_accepted=b_write_accepted,
            a_record_unchanged=a_record_unchanged),
    }
    return {"executed": True, "status": records["reading-history"]["status"],
            "reason": "Synthetic record tao boi A tren ID synthetic; "
                      "B thu doc + ghi de; anon thu doc.",
            "records": records,
            "note": "Chi dung storyId/chapterId synthetic tu env. Khong "
                    "enumerate ID, khong doc du lieu user khac."}


def ws3_cache_isolation(h: Harness, cfg: dict) -> dict:
    """Priority 3: A -> B -> A -> anon tren CUNG URL, phat hien staleness."""
    p = f"/truyen/{cfg['slug']}/doc/{cfg['chapter']}.html"
    rows, props, cfp = [], [], []
    for who in ("A", "B", "A", "anon"):
        rec = h.get(who, p, tag="ws3/cache", expect_deny=(who == "anon"))
        rows.append(rec)
        props.append(h.props(rec, h.text_of(rec)))
        cfp.append(h.content_fp(rec))
    cache_hit = any(("HIT" in (r["headers"].get("cf-cache-status") or "")
                     or r["headers"].get("Age") is not None) for r in rows)
    a_sha, b_sha, a2_sha = (cfp[0]["sha256"], cfp[1]["sha256"], cfp[2]["sha256"])
    session_rows = [
        {"label": "A", "locked": props[0]["locked"],
         "body_chars": props[0]["body_chars"], "content_sha": a_sha},
        {"label": "B", "locked": props[1]["locked"],
         "body_chars": props[1]["body_chars"], "content_sha": b_sha},
    ]
    classifier = cache_isolation_state(session_rows=session_rows,
                                       cache_hit_seen=cache_hit)
    return {"path": p, "order": ["A", "B", "A_again", "anon"],
            "rows": rows, "props": props, "content_fingerprints": cfp,
            "cache_hit_seen": cache_hit,
            "content_sha_A": a_sha, "content_sha_B": b_sha,
            "content_sha_A_again": a2_sha,
            "a_stable": a_sha == a2_sha,
            "b_distinct_from_a": b_sha != a_sha,
            "classifier_result": classifier,
            "status": (UNKNOWN if classifier.startswith("UNKNOWN") else OBSERVED),
            "note": "So sanh fingerprint NOI DUNG, khong so hash toan response "
                    "(metadata dong khac nhau giua cac request). Classifier yeu "
                    "cau A that su co entitlement. Khong ket luan leak chi tu "
                    "Vary/Cache-Control."}


def ws4_audio_entitlement(h: Harness, cfg: dict, a_entitled: bool | None = None) -> dict:
    """Priority 4: doi chieu audio giua A (duoc entitlement) va B (khong duoc).

    A thieu audio -> UNKNOWN (phép thu vo nghia), KHONG phai ket luan thanh
    cong. B co audio -> NEEDS_REVIEW.
    """
    p = f"/truyen/{cfg['slug']}/nghe/{cfg['chapter']}.html"
    out = {}
    for w in ("A", "B", "anon"):
        rec = h.get(w, p, tag="ws4/audio-page", expect_deny=(w == "anon"))
        out[w] = {"row": rec, "signals": audio_signals(h.text_of(rec))}
    out["audio_remaining"] = {w: h.get(w, "/api/user/audio-remaining",
                                       tag="ws4/quota") for w in ("A", "B", "anon")}
    a_has = out["A"]["signals"]["has_audio"]
    b_has = out["B"]["signals"]["has_audio"]
    state = audio_entitlement_state(a_has_audio=a_has, b_has_audio=b_has,
                                    a_entitled=a_entitled)
    return {"data": out,
            "a_has_audio": a_has,
            "b_has_audio": b_has,
            "a_entitled": a_entitled,
            "audio_state": state,
            "status": (UNKNOWN if state.startswith("UNKNOWN") else
                       OBSERVED if state == "OBSERVED_CONSISTENT"
                       else "OBSERVED_NEEDS_REVIEW"),
            "note": "Chi so sanh SU CO MAT cua audioUrl/media reference. "
                    "KHONG luu URL, KHONG tai audio. A thieu audio -> UNKNOWN. "
                    "Khong suy luan tu status 200 hay tu vi thieu header."}


def ws5_matcher(h: Harness, cfg: dict) -> dict:
    """Priority 5: re-verify middleware matcher tren build HIEN TAI, co fingerprint."""
    probes = ["", ".html", ".json", ".txt", ".css", ".png", ".", ".xhtml", "%2Ehtml"]
    base = f"/truyen/{cfg['slug']}/doc/{cfg['chapter']}"
    rows = []
    for suf in probes:
        r = h.get("anon", base + suf, tag="ws5/matcher", expect_deny=True)
        gated = "khong-co-pass" in (r["headers"].get("Location") or "")
        rows.append({"suffix": suf or "(none)", "status": r["status"],
                     "gated": gated, "body_sha256": r["body_sha256"]})
    fp_rows = {}
    for path, key in (("/sitemap.xml", "sitemap"), ("/api/config", "config")):
        r = h.get("anon", path, tag="ws5/fingerprint", expect_deny=True)
        fp_rows[key] = {"status": r["status"],
                        "body_sha256": r["body_sha256"], "bytes": r["bytes"]}
    return {"probes": rows, "fingerprint": fp_rows, "status": OBSERVED,
            "note": "Observed = co response that. Day la HANH VI gate, KHONG phai "
                    "authorization finding. Khong ket luan vulnerability tu 200 hay 307."}


# ---------------------------------------------------------------------- main
def plan_text(pr: dict) -> str:
    lines = [
        "TTM STAGING A/B AUDIT — KE HOACH (khong gui request nao)",
        f"  commit/env: prerequisites.ready={pr['ready']}",
        f"  staging: {pr['staging_host_message']}",
        f"  allowed staging hosts: {', '.join(pr['allowed_staging_hosts']) or '(chua set)'}",
        f"  sessions independent: {pr['sessions_independent']}",
        f"  mutate authorized: {pr['mutate_authorized']}",
        "",
        "  5 workstreams (chi GET neu khong co --allow-mutate):",
        "   WS1  A/B/anon tren /doc/<test-chapter>.html — fingerprint NOI DUNG",
        "   WS2  /api/reading-history, /api/favorites, /api/notifications,",
        "        /api/listening-history, /api/chapters/<test-id>/comments,",
        "        /api/user/audio-remaining",
        "        + phase 2 (chi khi --allow-mutate): tao record synthetic thuoc A,",
        "          kiem tra B doc/sua duoc khong, anon bi tu choi",
        "   WS3  A -> B -> A_again -> anon tren cung URL + Age/ETag/cf-cache-status",
        "   WS4  /nghe/<test-chapter>.html + /api/user/audio-remaining",
        "        A thieu audio -> UNKNOWN; B co audio -> NEEDS_REVIEW",
        "   WS5  9 dot-suffix probes + sitemap/config fingerprint",
        "",
        "  Evidence: status, header whitelist, SHA-256, synthetic marker,",
        "  fingerprint noi dung. KHONG log cookie/token, KHONG luu body/audio URL.",
        "  KHONG enumerate ID.",
        "",
    ]
    if pr["missing"]:
        lines.append("  THIEU: " + ", ".join(pr["missing"]))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true", help="in ke hoach, khong network")
    ap.add_argument("--write-plan", action="store_true",
                    help="ghi lai recon/staging_plan.json (chi khi muon refresh evidence)")
    ap.add_argument("--run", action="store_true", help="chay that tren staging")
    ap.add_argument("--allow-mutate", action="store_true",
                    help="cho phep POST tao test records (can TTM_MUTATE_AUTHORIZED=1)")
    ap.add_argument("--out", default="recon/staging_audit.json")
    args = ap.parse_args()

    pr = prerequisites()
    if args.plan or not args.run:
        print(plan_text(pr))
        if args.write_plan:
            Path("recon/staging_plan.json").write_text(
                json.dumps({"at": datetime.now(timezone.utc).isoformat(),
                            "prerequisites": pr, "plan": plan_text(pr)},
                           ensure_ascii=False, indent=2), encoding="utf-8")
            print("-> recon/staging_plan.json (refreshed)")
        return EXIT_OK if pr["ready"] else EXIT_NOT_READY

    if not pr["ready"]:
        return die(pr)
    if args.allow_mutate and not pr["mutate_authorized"]:
        print("--allow-mutate can TTM_MUTATE_AUTHORIZED=1", file=sys.stderr)
        return EXIT_NOT_READY

    cfg = {"slug": os.environ["TTM_TEST_SLUG"],
           "chapter": os.environ["TTM_TEST_CHAPTER"],
           "chapter_id": os.environ["TTM_TEST_CHAPTER_ID"],
           "story_id": os.environ["TTM_TEST_STORY_ID"]}
    host_ok, host_msg = staging_host_ok(os.environ["TTM_STAGING_URL"],
                                         allowed_hosts())
    if not host_ok:
        print(f"TU CHOI: {host_msg}", file=sys.stderr)
        return EXIT_NOT_READY

    h = Harness(os.environ["TTM_STAGING_URL"], args.allow_mutate, Path(args.out),
                mutate_authorized=pr["mutate_authorized"], verified_host=host_msg)
    payload = {"prerequisites": pr, "config": dict(cfg),
               "allow_mutate": args.allow_mutate,
               "sections": {}, "aborted": False,
               "verdict": {
                   "confirmed_vulnerabilities": [],
                   "note": "Khong tu dong ket luan. Moi section co status rieng; "
                           "can doi chieu props + fingerprint truoc khi nang up "
                           "thanh finding.",
               }}
    try:
        ws1 = ws1_session_isolation(h, cfg)
        payload["sections"]["ws1_session_isolation"] = ws1
        payload["sections"]["ws2_object_authz"] = ws2_object_authz(h, cfg)
        payload["sections"]["ws3_cache_isolation"] = ws3_cache_isolation(h, cfg)
        payload["sections"]["ws4_audio_entitlement"] = ws4_audio_entitlement(
            h, cfg, a_entitled=ws1.get("A_entitled"))
        payload["sections"]["ws5_matcher"] = ws5_matcher(h, cfg)
    except AbortRun as exc:
        payload["aborted"] = True
        payload["abort"] = {"status": exc.status, "path": exc.path,
                            "who": exc.who, "reason": "HTTP %d — dung ngay" % exc.status}
        print(f"ABORT: HTTP {exc.status} tai {exc.path} (session {exc.who}) — "
              "dung ngay, khong gui them request.", file=sys.stderr)
        h.flush(payload)
        return EXIT_ABORTED
    except WriteNotAuthorized as exc:
        payload["aborted"] = True
        payload["abort"] = {"reason": str(exc)}
        print(f"ABORT: {exc}", file=sys.stderr)
        h.flush(payload)
        return EXIT_ABORTED
    h.flush(payload)
    print(f"-> {args.out}  rows={len(h.rows)} writes={len(h.writes)}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
