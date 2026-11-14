#!/usr/bin/env python3
"""Audit 3 lop: server authorization / content delivery / cache isolation.

    python ttm_entitlement_audit.py                 # anonymous, khong can cookie
    python ttm_entitlement_audit.py --sweep        # quet toan bo TOC (51 chuong)
    TTM_COOKIE_A=... TTM_COOKIE_B=... python ttm_entitlement_audit.py --sessions

Rang buoc:
  - CHI GET. Khong POST mutate, khong brute force, khong doc file cau hinh/bi mat.
  - 1 luong, nghi 2s/request.
  - Khong log gia tri cookie that: chi log SHA-256 8 ky tu dau.
  - Mac dinh KHONG co cookie -> moi ket luan la anonymous; phan cache giua 2
    phien that chi co gia tri khi chay --sessions.

Output: recon/entitlement_audit.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

from ttm_recon import (chapter_body, flight_stream, iter_chunks,
                       parse_chapter_props, parse_chapters, strip_rsc_prefix)

ORIGIN = "https://tieuthuyetmang.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
SLUG = "thanh-lanh-su-ton-mu-mat-roi-sao-lai-thanh-benh-kieu-me-do-de-the-nay"
DELAY = 2.0
FREE, LOCKED = 1, 4

PARAMS = ["", "?preview=1", "?unlocked=1", "?vip=1", "?isPreview=1",
          "?force=1", "?admin=1", "?key=1", "?chapterId=1", "?content=full"]
PRIV_HEADERS = ["X-User-Role", "X-VIP", "X-Forwarded-User", "X-Original-URL",
                "X-Rewrite-URL", "X-Middleware-Subrequest"]

rep: dict = {"at": datetime.now(timezone.utc).isoformat(),
             "scope": "GET only, no config/secret file access",
             "sections": {}}


def fp(cookie: str | None) -> str:
    return "-" if not cookie else hashlib.sha256(cookie.encode()).hexdigest()[:8]


def get(path: str, *, extra: dict | None = None,
        cookie: str | None = None) -> requests.Response:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if extra:
        h.update(extra)
    if cookie:
        h["Cookie"] = cookie
    r = requests.get(ORIGIN + path, headers=h, timeout=25, allow_redirects=False)
    # Next.js khong tra charset cho text/x-component -> requests mac dinh
    # ISO-8859-1 lam tieng Viet bi mojibake va doi dai chuoi. Bat UTF-8.
    if "x-component" in (r.headers.get("Content-Type") or "") or r.encoding is None:
        r.encoding = "utf-8"
    time.sleep(DELAY)
    return r


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:10]


def path_for(n: int) -> str:
    return f"/truyen/{SLUG}/doc/{n}.html"


def resolve_content(stream: str, content_field) -> tuple[int, str]:
    """Do body theo tham chieu `content` ($1b / $15 / ...), khong hard-code chunk id.

    Tra (do dai, excerpt). Neu content rong -> (0, "").
    """
    if not isinstance(content_field, str) or not content_field.startswith("$"):
        return 0, ""
    cid = content_field[1:]
    for k, payload in iter_chunks(stream):
        if k != cid:
            continue
        text = strip_rsc_prefix(payload)
        return len(text), text[:160]
    # Fallback: chunk 1b (HTML full render) hoac chunk T-dai nhat.
    return len(strip_rsc_prefix(chapter_body(stream))), ""


def inspect(markup: str, ctype: str) -> dict:
    """Do noi dung o 3 kenh: DOM render san, flight stream, chunk text.

    Luu y: response `text/x-component` (header RSC:1) LA raw RSC stream, khong
    co the `self.__next_f.push(...)` -> phai doc truc tiep, khong go flight_stream.
    """
    is_rsc = "x-component" in (ctype or "")
    soup = None if is_rsc else BeautifulSoup(markup, "lxml")
    dom = 0
    if soup:
        node = soup.select_one("div.prose, .prose")
        dom = len(node.get_text("\n", strip=True)) if node else 0
    stream = markup if is_rsc else flight_stream(markup)
    props = parse_chapter_props(stream)
    body_len, body_excerpt = resolve_content(stream, props.get("content"))
    texts = [(cid, len(v)) for cid, v in iter_chunks(stream)
             if re.match(r"^T[0-9a-f]+,", v)]
    dec = json.JSONDecoder()
    longest = 0
    for m in re.finditer(r'"', stream):
        try:
            val, _ = dec.raw_decode(stream, m.start())
        except ValueError:
            continue
        if isinstance(val, str) and not val.startswith("http"):
            longest = max(longest, len(val))
    return {"locked": props.get("locked"), "content_field": props.get("content"),
            "body_chars": body_len, "body_excerpt": body_excerpt,
            "dom_prose_chars": dom,
            "text_chunks": texts[:4], "longest_string_chars": longest,
            "has_audio_url": bool(re.search(r"\.(?:mp3|m4a|aac|ogg|wav|m3u8)", stream)),
            "toc_size": len(parse_chapters(stream))}


# -------------------------------------------------- 1. Server authorization
def server_authorization() -> dict:
    p = path_for(LOCKED)
    out = {"client_params": [], "privilege_headers": [], "cookie_variants": []}
    for q in PARAMS:
        r = get(p + q)
        i = inspect(r.text, r.headers.get("Content-Type"))
        out["client_params"].append({"param": q or "(none)", "status": r.status_code,
                                     "bytes": len(r.content), "locked": i["locked"],
                                     "content": i["content_field"],
                                     "body_chars": i["body_chars"]})
    for h in PRIV_HEADERS:
        r = get(p, extra={h: "admin"})
        i = inspect(r.text, r.headers.get("Content-Type"))
        out["privilege_headers"].append({"header": h, "status": r.status_code,
                                         "locked": i["locked"],
                                         "content": i["content_field"],
                                         "body_chars": i["body_chars"]})
    for label, ck in (("none", None), ("fake_A", "probe_a=1111"),
                      ("fake_B", "probe_b=2222")):
        r = get(p, cookie=ck)
        i = inspect(r.text, r.headers.get("Content-Type"))
        out["cookie_variants"].append({"label": label, "cookie": "fake" if ck else "none",
                                       "status": r.status_code, "locked": i["locked"],
                                       "content": i["content_field"],
                                       "body_chars": i["body_chars"],
                                       "body_sha": sha(r.content)})
    return out


# ----------------------------------------------------- 2. Content delivery
def content_delivery(sweep: bool) -> dict:
    out = {"channels": [], "toc_consistency": []}
    for n, label in ((FREE, "free"), (LOCKED, "locked")):
        for ch, extra in (("html", {}), ("rsc", {"RSC": "1"}),
                          ("prefetch", {"Next-Router-Prefetch": "1", "Purpose": "prefetch"})):
            r = get(path_for(n), extra=extra)
            i = inspect(r.text, r.headers.get("Content-Type"))
            out["channels"].append({
                "chapter": n, "label": label, "channel": ch, "status": r.status_code,
                "content_type": r.headers.get("Content-Type"), "bytes": len(r.content),
                "cache_control": r.headers.get("Cache-Control"),
                "cf_cache_status": r.headers.get("cf-cache-status"),
                "vary": r.headers.get("Vary"), **{k: i[k] for k in
                                                   ("locked", "content_field", "body_chars",
                                                    "dom_prose_chars", "text_chunks",
                                                    "longest_string_chars", "has_audio_url")}})
    # API: co field body / audioUrl / chapterNumber nao khong?
    apis = ["/api/stories?limit=5", "/api/stories?include=chapters",
            "/api/config", "/api/favorites", "/api/notifications",
            "/api/user/audio-remaining",
            "/api/chapters/01KY3R1NDGX9TDNAQVWFEBBYQ9/comments"]
    out["api"] = []
    for p in apis:
        r = get(p)
        t = r.text
        out["api"].append({"path": p, "status": r.status_code, "bytes": len(r.content),
                           "has_content_field": bool(re.search(r'"content"\s*:', t)),
                           "has_body_field": bool(re.search(r'"(?:text|body|chapterText)"\s*:', t)),
                           "has_audio_url": bool(re.search(r"audioUrl|\.(?:mp3|m4a|m3u8)", t, re.I)),
                           "chapterNumber_count": t.count("chapterNumber"),
                           "isLocked_count": t.count("isLocked")})
    # Doi chieu TOC: isLocked[] vs props.locked tung chuong
    r = get(path_for(1))
    toc = parse_chapters(flight_stream(r.text))
    pick = toc if sweep else [c for c in toc if c["chapterNumber"] in (1, 2, 3, 4, 5, 26, 51)]
    for c in pick:
        n = c["chapterNumber"]
        rr = get(path_for(n))
        i = inspect(rr.text, rr.headers.get("Content-Type"))
        out["toc_consistency"].append({
            "chapter": n, "toc_isLocked": c.get("isLocked"),
            "page_locked": i["locked"], "body_chars": i["body_chars"],
            "dom_prose_chars": i["dom_prose_chars"],
            "consistent": (bool(c.get("isLocked")) == bool(i["locked"])
                           and (i["body_chars"] == 0 if c.get("isLocked") else i["body_chars"] > 0))})
    return out


# --------------------------------------------------------------- 3. Cache
def cache_isolation() -> dict:
    out = {"repeat": [], "key_variants": [], "vary_alternation": [], "sessions": None}
    for i in range(3):
        r = get("/api/config")
        out["repeat"].append({"i": i, "status": r.status_code, "bytes": len(r.content),
                              "body_sha": sha(r.content),
                              "cf": r.headers.get("cf-cache-status"),
                              "age": r.headers.get("Age"), "etag": r.headers.get("ETag")})
    cases = [("anon", path_for(1), None, None),
             ("fake_A", path_for(1), None, "probe_a=1111"),
             ("fake_B", path_for(1), None, "probe_b=2222"),
             ("authz_header", path_for(1), {"Authorization": "Bearer probe_dummy"}, None),
             ("query", path_for(1) + "?cachebust=xyz", None, None),
             ("css_ext", f"/truyen/{SLUG}/doc/1.css", None, None),
             ("png_ext", f"/truyen/{SLUG}/doc/1.png", None, None)]
    for label, p, extra, ck in cases:
        r = get(p, extra=extra, cookie=ck)
        out["key_variants"].append({"label": label, "path": p, "status": r.status_code,
                                    "bytes": len(r.content), "body_sha": sha(r.content),
                                    "cf": r.headers.get("cf-cache-status"),
                                    "age": r.headers.get("Age"),
                                    "cache_control": r.headers.get("Cache-Control"),
                                    "vary": r.headers.get("Vary"),
                                    "vary_has_cookie": "Cookie" in (r.headers.get("Vary") or ""),
                                    "set_cookie": bool(r.headers.get("Set-Cookie"))})
    for i, extra in enumerate(({"RSC": "1"}, {}, {"RSC": "1"}, {}, {"RSC": "1"})):
        r = get(path_for(LOCKED), extra=extra)
        out["vary_alternation"].append({"i": i, "req_rsc": bool(extra),
                                        "content_type": r.headers.get("Content-Type"),
                                        "bytes": len(r.content), "body_sha": sha(r.content),
                                        "cf": r.headers.get("cf-cache-status")})
    return out


def real_sessions(ca: str, cb: str) -> dict:
    """A→B→A tren CUNG URL. Phat hien neu B nhan duoc body cua A."""
    p = path_for(LOCKED)
    rows = []
    for label, ck in (("A", ca), ("B", cb), ("A_again", ca), ("anon", None)):
        r = get(p, cookie=ck)
        i = inspect(r.text, r.headers.get("Content-Type"))
        rows.append({"label": label, "cookie_fp": fp(ck), "status": r.status_code,
                     "bytes": len(r.content), "body_sha": sha(r.content),
                     "locked": i["locked"], "body_chars": i["body_chars"],
                     "dom_prose_chars": i["dom_prose_chars"],
                     "cf": r.headers.get("cf-cache-status"),
                     "set_cookie": bool(r.headers.get("Set-Cookie")),
                     "excerpt": strip_rsc_prefix(chapter_body(flight_stream(r.text)))[:120]})
    a_body = next((x["body_chars"] for x in rows if x["label"] == "A"), 0)
    b = next(x for x in rows if x["label"] == "B")
    return {"rows": rows,
            "A_body_chars": a_body,
            "B_body_chars": b["body_chars"],
            "B_received_A_content": a_body > 200 and b["body_chars"] > 200
                                    and b["body_sha"] == next(x["body_sha"] for x in rows if x["label"] == "A"),
            "interpretation": "Can A that su co entitlement (da mo khoa) de ket luan. "
                              "Neu A van locked=true thi ca 2 deu chua du dieu kien."}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", action="store_true", help="quet toan bo TOC")
    ap.add_argument("--sessions", action="store_true",
                    help="dung TTM_COOKIE_A / TTM_COOKIE_B de test cache giua 2 phien that")
    ap.add_argument("--out", default="recon/entitlement_audit.json")
    args = ap.parse_args()

    print("=== 1. Server authorization ===")
    rep["sections"]["server_authorization"] = server_authorization()
    s = rep["sections"]["server_authorization"]
    leaks = [x for group in ("client_params", "privilege_headers", "cookie_variants")
             for x in s[group] if x.get("body_chars", 0) > 0 or x.get("content")]
    print(f"  {len(PARAMS)} params + {len(PRIV_HEADERS)} headers + 3 cookie variants"
          f" -> leak candidates: {len(leaks)}")

    print("=== 2. Content delivery ===")
    rep["sections"]["content_delivery"] = content_delivery(args.sweep)
    cd = rep["sections"]["content_delivery"]
    for x in cd["channels"]:
        print(f"  ch.{x['chapter']} {x['label']:6} {x['channel']:8} "
              f"ct={str(x['content_type'])[:22]:22} locked={x['locked']} "
              f"content={repr(x['content_field'])[:8]:8} body={x['body_chars']:6} "
              f"dom={x['dom_prose_chars']:6}")
    bad = [x for x in cd["toc_consistency"] if not x["consistent"]]
    print(f"  TOC consistency: {len(cd['toc_consistency'])} chuong, bat thuong {len(bad)} {bad[:5]}")
    print(f"  API: {len(cd['api'])} endpoint, co content field: "
          f"{[x['path'] for x in cd['api'] if x['has_content_field']]}")

    print("=== 3. Cache ===")
    rep["sections"]["cache"] = cache_isolation()
    c = rep["sections"]["cache"]
    print(f"  /api/config x3: {[x['cf'] for x in c['repeat']]} hash="
          f"{[x['body_sha'] for x in c['repeat']]}")
    for x in c["key_variants"]:
        print(f"  {x['label']:14} cf={x['cf']:8} bytes={x['bytes']:7} "
              f"vary_cookie={x['vary_has_cookie']} setcookie={x['set_cookie']}")
    print(f"  RSC/HTML alternate: {[x['content_type'] for x in c['vary_alternation']]}")

    ca, cb = os.environ.get("TTM_COOKIE_A"), os.environ.get("TTM_COOKIE_B")
    if args.sessions and ca and cb:
        print("=== 3b. Real 2-session A->B->A ===")
        rep["sections"]["cache"]["sessions"] = real_sessions(ca, cb)
        for x in rep["sections"]["cache"]["sessions"]["rows"]:
            print(f"  {x['label']:8} fp={x['cookie_fp']} locked={x['locked']} "
                  f"body={x['body_chars']} sha={x['body_sha']}")
    else:
        rep["sections"]["cache"]["sessions_note"] = (
            "Chua co TTM_COOKIE_A/B -> chua chung minh duoc cache isolation giua "
            "phien da mo khoa va chua mo khoa. Chay lai voi --sessions.")

    Path(args.out).write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
