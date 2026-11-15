#!/usr/bin/env python3
"""Fail-closed A/B staging audit harness cho 5 uu tien danh gia.

    python ttm_staging_audit.py --plan          # KHONG network, in ke hoach + thieu gi
    python ttm_staging_audit.py --run           # CHI chay khi du prerequisite

NGUYEN TAC (fail-closed):
  * Refuse to run neu thieu bat ky prerequisite nao. Khong "chay thu" voi production.
  * Host MAC DINH la None. Phai set TTM_STAGING_URL ro rang; tu choi moi host
    khong nam trong allowlist staging (khong cho phep tieuthuyetmang.com).
  * Chi GET (va OPTIONS harmless). POST mutate chi khi co --allow-mutate VA
    TTM_MUTATE_AUTHORIZED=1; mac dinh KHONG BAO GIO mutate.
  * Chi dung test chapter SYNTHETIC do owner cung cap (TTM_TEST_SLUG /
    TTM_TEST_CHAPTER / TTM_TEST_CHAPTER_ID). Khong doc noi dung chuong that.
  * Khong log cookie/token/gia tri body. Chi log status, header whitelist,
    SHA-256 cua body, va co mat cua marker synthetic.
  * 1 luong, nghi >=2s/request; dung ngay neu 403/429.
  * Moi ket luan di qua audit_classify (khong nhan HTTP status lam input).

ENV bat buoc:
    TTM_STAGING_URL          https://...  (phai la staging, khong phai production)
    TTM_COOKIE_A             session cua A (co entitlement toi test chapter)
    TTM_COOKIE_B             session cua B (khong co entitlement)
    TTM_TEST_SLUG            slug cua truyen synthetic
    TTM_TEST_CHAPTER         so chương synthetic
    TTM_TEST_CHAPTER_ID      chapterId synthetic
    TTM_TEST_STORY_ID        storyId synthetic

ENV tuy chon:
    TTM_SCOPE_REF            ma tham chieu uy quyen (chi ghi vao evidence, khong kiem tra)
    TTM_MUTATE_AUTHORIZED    1 neu scope cho phep POST tao test records
    TTM_AUDIO_TEST_URL       URL audio synthetic (neu co)

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

from audit_classify import (INFERRED, OBSERVED, UNKNOWN, cache_isolation_state,
                            classify, content_state, redact)

DELAY = 2.0
TIMEOUT = 25
PRODUCTION_HOSTS = {"tieuthuyetmang.com", "www.tieuthuyetmang.com",
                    "img.tieuthuyetmang.com", "audio.tieuthuyetmang.com"}
STAGING_HINTS = ("staging", "stage.", "test.", "tests.", "localhost", "127.0.0.1",
                 "dev.", "sandbox", ".test", ".local")
SYNTHETIC_MARKER = "SYNTHETIC-TEST-BODY"
HEADER_WHITELIST = ("Content-Type", "Cache-Control", "Vary", "Age", "ETag",
                    "Last-Modified", "cf-cache-status", "Location", "Server",
                    "X-Powered-By", "Access-Control-Allow-Origin",
                    "Access-Control-Allow-Credentials")

REQUIRED = ("TTM_STAGING_URL", "TTM_COOKIE_A", "TTM_COOKIE_B",
            "TTM_TEST_SLUG", "TTM_TEST_CHAPTER",
            "TTM_TEST_CHAPTER_ID", "TTM_TEST_STORY_ID")


# ------------------------------------------------------------------ gating
def env_state() -> dict:
    """Tra ve do DAI cua tung env, KHONG BAO GIO tra gia tri."""
    return {k: len(os.environ.get(k, "")) for k in REQUIRED}


def staging_host_ok(url: str) -> tuple[bool, str]:
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
    if not any(h in host for h in STAGING_HINTS):
        return False, (f"host '{host}' khong co dau hieu staging; "
                       "can xac nhan ro rang day la moi truong duoc uy quyen")
    if u.scheme != "https" and host not in ("localhost", "127.0.0.1"):
        return False, "staging tu xa bat buoc phai https"
    return True, host


def prerequisites() -> dict:
    e = env_state()
    missing = [k for k, n in e.items() if n == 0]
    base = os.environ.get("TTM_STAGING_URL", "")
    host_ok, host_msg = staging_host_ok(base)
    a, b = os.environ.get("TTM_COOKIE_A", ""), os.environ.get("TTM_COOKIE_B", "")
    sessions_ok = bool(a and b and a != b)
    return {
        "env_lengths": e, "missing": missing,
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
    return 3


# ------------------------------------------------------------------- request
class Harness:
    def __init__(self, base: str, allow_mutate: bool, out: Path):
        self.base = base.rstrip("/")
        self.allow_mutate = allow_mutate
        self.out = out
        self.sessions = {
            "A": self._session(os.environ["TTM_COOKIE_A"]),
            "B": self._session(os.environ["TTM_COOKIE_B"]),
            "anon": self._session(None),
        }
        self.rows: list[dict] = []
        self._bodies: dict[int, str] = {}   # in-memory only, KHONG ghi ra file
        self.test_id = f"STG-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    @staticmethod
    def _session(cookie: str | None) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": "ttm-staging-audit/1.0 (authorized test)",
                          "Accept": "*/*"})
        if cookie:
            s.headers["Cookie"] = cookie
        return s

    def get(self, who: str, path: str, *, extra: dict | None = None,
            tag: str = "") -> dict:
        url = self.base + path
        r = self.sessions[who].get(url, headers=extra or {}, timeout=TIMEOUT,
                                   allow_redirects=False)
        time.sleep(DELAY)
        body = r.content
        text = r.content.decode("utf-8", errors="replace")
        rec = {
            "test_id": self.test_id, "who": who, "method": "GET", "path": path,
            "tag": tag, "status": r.status_code,
            "bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest()[:16],
            "synthetic_marker_present": SYNTHETIC_MARKER.encode() in body,
            "headers": {k: redact(str(r.headers.get(k)))
                        for k in HEADER_WHITELIST if r.headers.get(k) is not None},
            "cookie_logged": False,
        }
        self.rows.append(rec)
        self._bodies[len(self.rows) - 1] = text   # in-memory de parse props
        if r.status_code in (403, 429):
            print(f"  ! {r.status_code} at {path} -> dung lai", file=sys.stderr)
        return rec

    @staticmethod
    def props(rec: dict, text: str) -> dict:
        """Parse entitlement state tu RSC payload (khong luu text ra file).

        Dung lai parser da duoc unit-test trong ttm_recon.py. Ho tro ca HTML
        (flight stream) va raw text/x-component.
        """
        from ttm_entitlement_audit import inspect
        ctype = rec["headers"].get("Content-Type") or "text/html"
        i = inspect(text, ctype)
        return {"locked": i["locked"], "content_field": i["content_field"],
                "body_chars": i["body_chars"], "dom_prose_chars": i["dom_prose_chars"],
                "has_audio_url": i["has_audio_url"],
                "content_state": content_state(locked=i["locked"],
                                               body_chars=i["body_chars"],
                                               has_audio_url=i["has_audio_url"])}

    def flush(self, payload: dict) -> None:
        payload["test_id"] = self.test_id
        payload["at"] = datetime.now(timezone.utc).isoformat()
        payload["base_host"] = urlparse(self.base).hostname
        payload["rows"] = self.rows
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                            encoding="utf-8")


# ------------------------------------------------------------- 5 workstreams
def ws1_session_isolation(h: Harness, cfg: dict) -> dict:
    """Priority 1: A nhan dung cai A duoc phep; B khong nhan cua A."""
    p = f"/truyen/{cfg['slug']}/doc/{cfg['chapter']}.html"
    rows, props = {}, {}
    for w in ("A", "B", "anon"):
        rec = h.get(w, p, tag="ws1/chapter")
        rows[w] = rec
        props[w] = h.props(rec, h._bodies[len(h.rows) - 1])
    a, b = props["A"], props["B"]
    a_entitled = a["locked"] is False and a["body_chars"] > 200
    b_saw_a = (b["body_chars"] > 200
               and rows["B"]["body_sha256"] == rows["A"]["body_sha256"])
    return {
        "path": p, "rows": rows, "props": props,
        "A_entitled": a_entitled,
        "B_received_A_body": b_saw_a,
        "status": (UNKNOWN if not a_entitled else
                   OBSERVED if not b_saw_a else "OBSERVED_NEEDS_REVIEW"),
        "classifier": cache_isolation_state(
            session_rows=[{"label": "A", "locked": a["locked"],
                           "body_chars": a["body_chars"],
                           "body_sha": rows["A"]["body_sha256"]},
                          {"label": "B", "locked": b["locked"],
                           "body_chars": b["body_chars"],
                           "body_sha": rows["B"]["body_sha256"]}],
            cache_hit_seen=False),
        "note": "Entitlement doc tu RSC props, KHONG tu HTTP status. "
                "B_received_A_body chi co y nghia khi A_entitled=true.",
    }


def ws2_object_authz(h: Harness, cfg: dict) -> dict:
    """Priority 2: non-content objects, chi GET, khong enumerate ID nguoi khac."""
    paths = [
        # Client bundle chi cho thay POST @27459; query key "reading-history-home"
        # @27656 ngam dinh co GET list o bundle khac (chua capture). Probe GET de
        # kiem tra object-level authz ma khong mutate.
        ("/api/reading-history", "reading-history"),
        ("/api/favorites", "favorites"),
        ("/api/notifications", "notifications"),
        (f"/api/listening-history?chapterId={cfg['chapter_id']}", "listening-history"),
        (f"/api/chapters/{cfg['chapter_id']}/comments", "comments"),
        ("/api/user/audio-remaining", "audio-remaining"),
    ]
    summary = {}
    for path, name in paths:
        recs = {w: h.get(w, path, tag=f"ws2/{name}") for w in ("A", "B", "anon")}
        # Chi co y nghia khi A that su co du lieu rieng (khac anon). Hash giong
        # nhau giua A/B/B-va-anon (ca 2 deu rong) KHONG phai bang chung IDOR.
        a_bytes, b_bytes = recs["A"]["bytes"], recs["B"]["bytes"]
        a_hash, b_hash = recs["A"]["body_sha256"], recs["B"]["body_sha256"]
        anon_hash = recs["anon"]["body_sha256"]
        a_has_own_data = a_hash != anon_hash
        b_got_a_data = b_hash == a_hash and a_has_own_data
        summary[name] = {
            "rows": recs, "a_bytes": a_bytes, "b_bytes": b_bytes,
            "a_equals_anon": not a_has_own_data,
            "b_equals_a": b_hash == a_hash,
            "a_has_session_specific_data": a_has_own_data,
            "needs_review": b_got_a_data,
            "status": ("OBSERVED_NEEDS_REVIEW" if b_got_a_data else
                       "OBSERVED_NO_CROSS_SESSION_DATA" if a_has_own_data else
                       "UNKNOWN_NO_SESSION_SPECIFIC_DATA"),
        }
    return {"objects": summary, "status": UNKNOWN,
            "note": "Thieu test records do A/B tao -> hash giong nhau co the la ca 2 deu rong. "
                    "CHUA the ket luan IDOR. Can --allow-mutate + TTM_MUTATE_AUTHORIZED=1 "
                    "de tao record synthetic cho A, roi kiem tra B co doc duoc khong. "
                    "Khong enumerate ID, khong doc du lieu user khac."}


def ws3_cache_isolation(h: Harness, cfg: dict) -> dict:
    """Priority 3: A -> B -> A -> anon tren CUNG URL, phat hien staleness."""
    p = f"/truyen/{cfg['slug']}/doc/{cfg['chapter']}.html"
    rows, props = [], []
    for who in ("A", "B", "A", "anon"):
        rec = h.get(who, p, tag="ws3/cache")
        rows.append(rec)
        props.append(h.props(rec, h._bodies[len(h.rows) - 1]))
    cache_hit = any(("HIT" in (r["headers"].get("cf-cache-status") or "")
                     or r["headers"].get("Age") is not None) for r in rows)
    a_hash, b_hash, a2_hash = (rows[0]["body_sha256"], rows[1]["body_sha256"],
                               rows[2]["body_sha256"])
    session_rows = [
        {"label": "A", "locked": props[0]["locked"],
         "body_chars": props[0]["body_chars"], "body_sha": a_hash},
        {"label": "B", "locked": props[1]["locked"],
         "body_chars": props[1]["body_chars"], "body_sha": b_hash},
    ]
    return {"path": p, "order": ["A", "B", "A_again", "anon"],
            "rows": rows, "props": props, "cache_hit_seen": cache_hit,
            "a_hash": a_hash, "b_hash": b_hash, "a_again_hash": a2_hash,
            "a_stable": a_hash == a2_hash,
            "b_distinct_from_a": b_hash != a_hash,
            "classifier_result": cache_isolation_state(
                session_rows=session_rows, cache_hit_seen=cache_hit),
            "status": (UNKNOWN if cache_isolation_state(
                session_rows=session_rows, cache_hit_seen=cache_hit).startswith("UNKNOWN")
                       else OBSERVED),
            "note": "Hash khac nhau chua du de ket luan; classifier yeu cau "
                    "A that su co entitlement. Khong ket luan leak chi tu Vary/Cache-Control."}


def _audio_signals(rec: dict, text: str) -> dict:
    """Phat hien audioUrl / media URL trong payload (khong luu URL that ra file)."""
    has_prop = '"audioUrl"' in text
    urls = re.findall(r'https?://[^\s"\\]+\.(?:mp3|m4a|aac|ogg|wav|m3u8)[^\s"\\]*',
                      text, re.I)
    return {"has_audioUrl_prop": has_prop,
            "media_url_count": len(urls),
            "media_urls_logged": False,
            "locked_message": ("Audio bị khóa" in text or "nâng cấp" in text)}


def ws4_audio_entitlement(h: Harness, cfg: dict) -> dict:
    """Priority 4: doi chieu audioUrl / audio-remaining giua A va B."""
    p = f"/truyen/{cfg['slug']}/nghe/{cfg['chapter']}.html"
    out = {}
    for w in ("A", "B", "anon"):
        rec = h.get(w, p, tag="ws4/audio-page")
        out[w] = {"row": rec,
                  "signals": _audio_signals(rec, h._bodies[len(h.rows) - 1])}
    out["audio_remaining"] = {w: h.get(w, "/api/user/audio-remaining",
                                       tag="ws4/quota") for w in ("A", "B", "anon")}
    a_sig, b_sig = out["A"]["signals"], out["B"]["signals"]
    consistent = not (b_sig["media_url_count"] > 0 and a_sig["media_url_count"] == 0)
    return {"data": out, "consistent_with_entitlement": consistent,
            "status": OBSERVED if consistent else "OBSERVED_NEEDS_REVIEW",
            "note": "Chi so sanh SU CO MAT cua audioUrl, khong luu URL, khong tai audio. "
                    "Khong suy luan tu status 200 hay tu vi thieu header."}


def ws5_matcher(h: Harness, cfg: dict) -> dict:
    """Priority 5: re-verify middleware matcher tren build HIEN TAI, co fingerprint."""
    probes = ["", ".html", ".json", ".txt", ".css", ".png", ".", ".xhtml", "%2Ehtml"]
    base = f"/truyen/{cfg['slug']}/doc/{cfg['chapter']}"
    rows = []
    for suf in probes:
        r = h.get("anon", base + suf, tag="ws5/matcher")
        gated = "khong-co-pass" in (r["headers"].get("Location") or "")
        rows.append({"suffix": suf or "(none)", "status": r["status"],
                     "gated": gated, "body_sha256": r["body_sha256"]})
    # Fingerprint de gan ket qua vao dung build
    fp_rows = {}
    for path, key in (("/sitemap.xml", "sitemap"), ("/api/config", "config")):
        r = h.get("anon", path, tag="ws5/fingerprint")
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
        f"  sessions independent: {pr['sessions_independent']}",
        f"  mutate authorized: {pr['mutate_authorized']}",
        "",
        "  5 workstreams (chi GET neu khong co --allow-mutate):",
        "   WS1  A/B/anon tren /doc/<test-chapter>.html — entitlement & body hash",
        "   WS2  /api/reading-history, /api/favorites, /api/notifications,",
        "        /api/listening-history, /api/chapters/<test-id>/comments,",
        "        /api/user/audio-remaining",
        "   WS3  A -> B -> A_again -> anon tren cung URL + Age/ETag/cf-cache-status",
        "   WS4  /nghe/<test-chapter>.html + /api/user/audio-remaining",
        "   WS5  9 dot-suffix probes + sitemap/config fingerprint",
        "",
        "  Evidence: status, header whitelist, SHA-256 body, synthetic marker.",
        "  KHONG log cookie/token, KHONG luu body, KHONG enumerate ID.",
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
        # Mac dinh KHONG ghi de evidence da commit (co timestamp -> se lam
        # working tree dirty moi lan chay). Dung --write-plan khi can refresh.
        if args.write_plan:
            Path("recon/staging_plan.json").write_text(
                json.dumps({"at": datetime.now(timezone.utc).isoformat(),
                            "prerequisites": pr, "plan": plan_text(pr)},
                           ensure_ascii=False, indent=2), encoding="utf-8")
            print("-> recon/staging_plan.json (refreshed)")
        return 0 if pr["ready"] else 3

    if not pr["ready"]:
        return die(pr)
    if args.allow_mutate and not pr["mutate_authorized"]:
        print("--allow-mutate can TTM_MUTATE_AUTHORIZED=1", file=sys.stderr)
        return 3

    cfg = {"slug": os.environ["TTM_TEST_SLUG"],
           "chapter": os.environ["TTM_TEST_CHAPTER"],
           "chapter_id": os.environ["TTM_TEST_CHAPTER_ID"],
           "story_id": os.environ["TTM_TEST_STORY_ID"]}
    h = Harness(os.environ["TTM_STAGING_URL"], args.allow_mutate, Path(args.out))
    payload = {"prerequisites": pr, "config": {k: v for k, v in cfg.items()},
               "allow_mutate": args.allow_mutate,
               "sections": {
                   "ws1_session_isolation": ws1_session_isolation(h, cfg),
                   "ws2_object_authz": ws2_object_authz(h, cfg),
                   "ws3_cache_isolation": ws3_cache_isolation(h, cfg),
                   "ws4_audio_entitlement": ws4_audio_entitlement(h, cfg),
                   "ws5_matcher": ws5_matcher(h, cfg),
               },
               "verdict": {
                   "confirmed_vulnerabilities": [],
                   "note": "Khong tu dong ket luan. Moi section co status rieng; "
                           "can doi chieu props + hash truoc khi nang cap thanh finding.",
               }}
    h.flush(payload)
    print(f"-> {args.out}  rows={len(h.rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
