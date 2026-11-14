#!/usr/bin/env python3
"""Control-layer audit cho tieuthuyetmang.com.

Trả lời 3 câu hỏi KHÔNG được suy luận:
  1. Route có đi qua access gate không? (layer L1)
  2. Trang có hiển thị nội dung chương không? (layer L4: DOM vs RSC payload)
  3. API phía server có thực sự cấp dữ liệu bị khoá không? (layer L3)

Và retest F2 Information Disclosure + kiểm tra cấu hình bảo mật.

Ràng buộc:
  - CHỈ GET/OPTIONS. Không POST mutate, không brute force, không thử
    /.env, /.git/*, /package.json hay bất kỳ file cấu hình/bí mật nào.
  - 1 luồng, nghỉ 2s/request.
  - Lưu response thô (có chừng mực) vào recon/audit/ trước khi kết luận.
  - Không log giá trị cookie/token.

    python ttm_control_audit.py
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ORIGIN = "https://tieuthuyetmang.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
DELAY = 2.0
SLUG = "thanh-lanh-su-ton-mu-mat-roi-sao-lai-thanh-benh-kieu-me-do-de-the-nay"
OUT = Path("recon/audit")
OUT.mkdir(parents=True, exist_ok=True)

# Pattern phân loại thông tin lộ ra. Không phải "có match = có lỗ hổng".
PATTERNS = {
    "php_version": r"PHP/\d|X-Powered-By:\s*PHP|phpinfo|\.php\b",
    "framework_name": r"Next\.js|NextAuth\.js|next-auth|__next_f|/_next/",
    "framework_version": r"next@\d|Next\.js\s*\d|react@\d|node\.js/\d|v\d+\.\d+\.\d+",
    "internal_fs_path": r"/var/www|/home/\w+|/app/(?:src|server)|\.next/server|node_modules/|C:\\\\|[A-Z]:\\\\",
    "stack_trace": r"\bat\s+(?:Object|async|Module|processTicksAndRejections)\b|\.js:\d+:\d+\)?\s*$",
    "exception_class": r"\bError:\s|\bTypeError:|\bPrismaClient|\bSQLException|Unhandled\s+|ECONNREFUSED",
    "sql": r"\bSELECT\b.{0,40}\bFROM\b|\bINSERT INTO\b|prisma\.|\bwhere:\s*\{",
    "secret_like": r"(?:sk|pk)_live_|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]\s*['\"]|DATABASE_URL|NEXTAUTH_SECRET|JWT_SECRET",
    "env_var": r"process\.env\.[A-Z_]+",
}

SEC_HEADERS = ("Strict-Transport-Security", "Content-Security-Policy",
               "X-Frame-Options", "X-Content-Type-Options",
               "Referrer-Policy", "Permissions-Policy", "X-Powered-By",
               "Server")

report: dict = {"at": datetime.now(timezone.utc).isoformat(),
                "origin": ORIGIN, "method": "GET/OPTIONS only",
                "no_auth_cookie": True, "sections": {}}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:12]


def save(name: str, text: str) -> None:
    # Chỉ lưu 4000 ký tự đầu — đủ làm bằng chứng, không kéo cả trang.
    (OUT / name).write_text(text[:4000], encoding="utf-8")


def req(path: str, *, headers: dict | None = None,
        method: str = "GET") -> requests.Response:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    r = requests.request(method, ORIGIN + path, headers=h, timeout=25,
                         allow_redirects=False)
    time.sleep(DELAY)
    return r


def hdr(r: requests.Response, keys) -> dict:
    return {k: r.headers.get(k) for k in keys}


# ---------------------------------------------------------------- L1: gate
def audit_gate() -> dict:
    paths = [
        "/", "/truyen", f"/truyen/{SLUG}", "/dang-nhap", "/khong-co-pass",
        "/robots.txt", "/sitemap.xml",
        f"/truyen/{SLUG}/doc/1", f"/truyen/{SLUG}/doc/1.html",
        f"/truyen/{SLUG}/doc/4", f"/truyen/{SLUG}/doc/4.html",
        f"/truyen/{SLUG}/nghe/1", f"/truyen/{SLUG}/nghe/1.html",
        "/api/config", "/api/stories", "/api/favorites", "/api/auth/session",
        "/_next/static/chunks/webpack-d24d2342890c2f44.js",
        "/api/config.html", "/dang-nhap.html", "/truyen.html",
    ]
    rows = []
    for p in paths:
        r = req(p)
        loc = r.headers.get("Location")
        state = ("GATE_REDIRECT" if loc and "khong-co-pass" in loc
                 else "NO_GATE" if r.status_code == 200
                 else f"HTTP_{r.status_code}")
        rows.append({"path": p, "status": r.status_code, "state": state,
                     "location": loc, "bytes": len(r.content),
                     "body_sha": sha(r.content)})
    # Kiểm chứng: gate bỏ qua MỌI path có dấu chấm ở segment cuối,
    # không riêng `.html`. Đây là bằng chứng xác định matcher của middleware.
    suffixes = ["", ".html", ".json", ".txt", ".css", ".png", ".", ".xhtml",
                "%2Ehtml", ".html/x"]
    dots = []
    for suf in suffixes:
        p = f"/truyen/{SLUG}/doc/1{suf}"
        r = req(p)
        dots.append({"suffix": suf or "(none)", "status": r.status_code,
                     "gated": "khong-co-pass" in (r.headers.get("Location") or ""),
                     "bytes": len(r.content)})
    r = req(f"/truyen/{SLUG}/doc/1")
    gate_headers = {k: v for k, v in r.headers.items()
                    if k.lower().startswith(("x-middleware", "x-nextjs", "location", "server"))}
    return {"rows": rows, "dot_suffix_probe": dots,
            "gate_response_headers": gate_headers}


# -------------------------------------------------- L2/L3/L4: nội dung chương
def audit_chapter_content() -> dict:
    from ttm_recon import (chapter_body, flight_stream, parse_chapter_props,
                           parse_chapters, strip_rsc_prefix)
    from bs4 import BeautifulSoup

    out = {"chapters": {}, "api": []}
    for n, label in ((1, "free"), (4, "locked")):
        p = f"/truyen/{SLUG}/doc/{n}.html"
        r = req(p)
        save(f"doc_{n}.html", r.text)
        stream = flight_stream(r.text)
        props = parse_chapter_props(stream)
        body = strip_rsc_prefix(chapter_body(stream))

        # DOM render sẵn (L4) — tách biệt hoàn toàn với RSC payload
        soup = BeautifulSoup(r.text, "lxml")
        dom_nodes = {}
        for sel in ("article", "div.prose, .prose", "[class*=whitespace-pre-wrap]"):
            node = soup.select_one(sel)
            dom_nodes[sel] = len(node.get_text("\n", strip=True)) if node else 0
        full_dom_text = soup.get_text(" ", strip=True)

        # Chuỗi dài nhất trong payload (dù không nằm ở chunk 1b) — để chứng minh
        # không có body bị giấu chỗ khác.
        dec = json.JSONDecoder()
        longest, longest_at = "", -1
        for m in re.finditer(r'"', stream):
            try:
                val, _ = dec.raw_decode(stream, m.start())
            except ValueError:
                continue
            if isinstance(val, str) and not val.startswith("http") and len(val) > len(longest):
                longest, longest_at = val, m.start()

        out["chapters"][label] = {
            "url": p, "status": r.status_code, "bytes": len(r.content),
            "props": {k: props.get(k) for k in
                      ("chapterNumber", "chapterId", "chapterTitle", "content",
                       "locked", "remainingDailyUnlocks", "nextChapterLocked")},
            "rsc_content_field": repr(props.get("content"))[:80],
            "rsc_body_chars": len(body),
            "rsc_body_excerpt": body[:160],
            "longest_payload_string_chars": len(longest),
            "longest_payload_string_at": longest_at,
            "longest_payload_string_excerpt": longest[:160],
            "dom_selector_chars": dom_nodes,
            "dom_total_chars": len(full_dom_text),
            "dom_mentions_locked": any(k in full_dom_text for k in
                                       ("mở khóa", "khoá", "khóa", "VIP", "nâng cấp")),
            "contains_audio_url": bool(re.search(r"\.(?:mp3|m4a|aac|ogg|wav|m3u8)", stream)),
            "toc_size": len(parse_chapters(stream)),
        }

    # L3: các API đã biết có trả body chương / audioUrl không?
    cid = out["chapters"]["locked"]["props"].get("chapterId")
    api_paths = [
        "/api/stories?limit=5", "/api/config", "/api/favorites",
        "/api/notifications", "/api/listening-history",
        "/api/user/audio-remaining", "/api/search?q=a", "/api/recommend",
        "/api/categories", f"/api/chapters/{cid}/comments",
        f"/api/chapters/{cid}/comments?limit=100",
    ]
    for p in api_paths:
        r = req(p)
        t = r.text
        rec = {"path": p, "status": r.status_code, "bytes": len(r.content),
               "content_type": r.headers.get("Content-Type"),
               "has_content_field": bool(re.search(r'"content"\s*:', t)),
               "has_body_like_field": bool(re.search(r'"(?:text|body|chapterText|html)"\s*:', t)),
               "has_audio_url": bool(re.search(r'audioUrl|\.(?:mp3|m4a|m3u8)', t, re.I)),
               "max_string_chars": 0, "excerpt": t[:160], "body_sha": sha(r.content)}
        try:
            d = r.json()
            rec["json_keys"] = sorted(d.keys())[:12] if isinstance(d, dict) else f"list[{len(d)}]"
            vals = []
            def walk(x):
                if isinstance(x, str):
                    vals.append(len(x))
                elif isinstance(x, dict):
                    for v in x.values(): walk(v)
                elif isinstance(x, list):
                    for v in x: walk(v)
            walk(d)
            rec["max_string_chars"] = max(vals, default=0)
        except ValueError:
            rec["json_keys"] = "non-json"
        out["api"].append(rec)
    return out


# ------------------------------------------------------------ F2 / lỗi / info
def audit_errors() -> dict:
    from ttm_recon import flight_stream
    cases = [
        ("404_page", "/truyen/does-not-exist-xyz/doc/999999.html"),
        ("404_api", "/api/route-that-does-not-exist"),
        ("400_nextauth", "/api/auth/me"),
        ("405_unlock", "/api/chapters/01KY3R17HH3FKCADAN8KKB949F/unlock"),
        ("gate_error", "/khong-co-pass?error=1&next=%2Ftruyen"),
        ("bad_param", "/api/stories?limit=not-a-number"),
        ("bad_chapter", "/api/chapters/not-a-valid-id/comments"),
        ("bad_search", "/api/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ]
    rows = []
    for label, p in cases:
        r = req(p)
        t = r.text
        save(f"error_{label}.txt", t)
        found = {k: bool(re.search(v, t, re.I | re.M)) for k, v in PATTERNS.items()}
        # Trích đoạn match thật (nếu có) để không kết luận suông
        snippets = {}
        for k, v in PATTERNS.items():
            m = re.search(v, t, re.I | re.M)
            if m:
                snippets[k] = t[max(0, m.start() - 60):m.end() + 60].replace("\n", " ")[:180]
        rows.append({"label": label, "path": p, "status": r.status_code,
                     "bytes": len(r.content), "body_sha": sha(r.content),
                     "headers": {k: r.headers.get(k) for k in
                                 ("Server", "X-Powered-By", "Content-Type",
                                  "Cache-Control", "x-nextjs-cache")},
                     "patterns_found": found, "snippets": snippets,
                     "excerpt": t[:200]})
    return {"cases": rows,
            "note": "Không thực hiện request nào tới /.env, /.git/*, /package.json, "
                    "file cấu hình hay bí mật. Chỉ quan sát response lỗi tự nhiên."}


# ------------------------------------------------------------- cấu hình bảo mật
def audit_config() -> dict:
    out = {}
    # Security headers trên 4 loại response
    sh = {}
    for label, p in (("page", "/dang-nhap"), ("api", "/api/config"),
                     ("notfound", "/api/nope-xyz"), ("gate", "/khong-co-pass")):
        r = req(p)
        sh[label] = {"status": r.status_code,
                     "headers": hdr(r, SEC_HEADERS),
                     "cache_control": r.headers.get("Cache-Control"),
                     "vary": r.headers.get("Vary"),
                     "cf_cache_status": r.headers.get("cf-cache-status")}
    out["security_headers"] = sh

    # CORS: nhiều Origin + preflight
    cors = []
    origins = ["https://evil.example", "null", "https://tieuthuyetmang.com",
               "https://sub.tieuthuyetmang.com",
               "https://tieuthuyetmang.com.evil.example"]
    for o in origins:
        r = req("/api/favorites", headers={"Origin": o})
        cors.append({"origin": o, "status": r.status_code,
                     "acao": r.headers.get("Access-Control-Allow-Origin"),
                     "acac": r.headers.get("Access-Control-Allow-Credentials"),
                     "vary": r.headers.get("Vary")})
    pre = req("/api/favorites", method="OPTIONS", headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"})
    cors.append({"origin": "PREFLIGHT OPTIONS", "status": pre.status_code,
                 "acao": pre.headers.get("Access-Control-Allow-Origin"),
                 "acac": pre.headers.get("Access-Control-Allow-Credentials"),
                 "acam": pre.headers.get("Access-Control-Allow-Methods"),
                 "acah": pre.headers.get("Access-Control-Allow-Headers")})
    out["cors"] = cors

    # Cookie flags (không log giá trị)
    cookies = []
    for p in ("/api/auth/session", "/api/auth/csrf", "/api/auth/providers"):
        r = req(p)
        raw = r.headers.get("Set-Cookie") or ""
        for part in re.split(r",(?=\s*__|\s*[A-Za-z_][A-Za-z0-9_-]*=)", raw):
            name = part.split("=", 1)[0].strip()
            if not name:
                continue
            cookies.append({"from": p, "name": name,
                            "HttpOnly": "HttpOnly" in part,
                            "Secure": "Secure" in part,
                            "SameSite": (re.search(r"SameSite=(\w+)", part) or [None, None])[1]
                            if re.search(r"SameSite=(\w+)", part) else None,
                            "Path": (re.search(r"Path=([^;]+)", part) or [None, None])[1],
                            "has_Domain": "Domain=" in part,
                            # __Host-: Secure + Path=/ + KHÔNG Domain.
                            # __Secure-: Secure, KHÔNG bắt buộc Path=/ hay no-Domain.
                            "prefix": ("__Host-" if name.startswith("__Host-")
                                       else "__Secure-" if name.startswith("__Secure-")
                                       else "none"),
                            "prefix_rules_ok": (
                                name.startswith("__Host-")
                                and "Secure" in part and "Domain=" not in part
                                and "Path=/" in part
                            ) if name.startswith("__Host-") else (
                                name.startswith("__Secure-") and "Secure" in part
                            ) if name.startswith("__Secure-") else None,
                            "value_logged": False})
    out["cookies"] = cookies

    # Cache policy trên các route đại diện
    cache = []
    for p in ("/api/config", "/api/stories", "/api/favorites",
              "/api/notifications", "/api/user/audio-remaining",
              "/api/auth/session", "/api/auth/csrf", "/api/listening-history",
              "/dang-nhap", f"/truyen/{SLUG}/doc/1.html",
              "/api/nope-xyz"):
        r = req(p)
        cc = r.headers.get("Cache-Control") or ""
        cache.append({"path": p, "status": r.status_code,
                      "cache_control": cc,
                      "duplicate_private": cc.count("private") > 1 or cc.count("no-store") > 1,
                      "conflicting_public_private": "public" in cc and ("private" in cc or "no-store" in cc),
                      "vary": r.headers.get("Vary"),
                      "vary_has_cookie": "Cookie" in (r.headers.get("Vary") or ""),
                      "cf_cache_status": r.headers.get("cf-cache-status"),
                      "etag": r.headers.get("ETag")})
    out["cache"] = cache
    return out


def main() -> int:
    print("=== L1: route co di qua access gate? ===")
    report["sections"]["gate"] = audit_gate()
    for x in report["sections"]["gate"]["rows"]:
        print(f"  {x['state']:14} {x['status']} {x['path'][:66]}")

    print("\n=== L2/L3/L4: noi dung chuong co that su duoc cap? ===")
    report["sections"]["content"] = audit_chapter_content()
    for k, v in report["sections"]["content"]["chapters"].items():
        print(f"  {k}: status={v['status']} rsc_content={v['rsc_content_field']} "
              f"body={v['rsc_body_chars']} dom_prose={v['dom_selector_chars']} "
              f"longest_payload={v['longest_payload_string_chars']} "
              f"audio_url={v['contains_audio_url']}")
    for a in report["sections"]["content"]["api"]:
        print(f"  API {a['status']} {a['path'][:52]:52} content={a['has_content_field']} "
              f"audio={a['has_audio_url']} maxstr={a['max_string_chars']}")

    print("\n=== F2 / xu ly loi ===")
    report["sections"]["errors"] = audit_errors()
    for c in report["sections"]["errors"]["cases"]:
        hits = [k for k, v in c["patterns_found"].items() if v]
        print(f"  {c['label']:14} {c['status']} bytes={c['bytes']:6} hits={hits}")

    print("\n=== Cau hinh bao mat ===")
    report["sections"]["config"] = audit_config()
    for k, v in report["sections"]["config"]["security_headers"].items():
        missing = [h for h in SEC_HEADERS[:6] if not v["headers"].get(h)]
        print(f"  headers[{k}]: thieu {len(missing)}/6 {missing}")
    for c in report["sections"]["config"]["cors"]:
        print(f"  CORS {c['origin'][:42]:42} -> ACAO={c.get('acao')} status={c['status']}")
    for c in report["sections"]["config"]["cookies"]:
        print(f"  cookie {c['name']:38} HttpOnly={c['HttpOnly']} Secure={c['Secure']} "
              f"SameSite={c['SameSite']} prefix={c['prefix']} rules_ok={c['prefix_rules_ok']}")
    for c in report["sections"]["config"]["cache"]:
        print(f"  cache {c['path'][:46]:46} conflict={c['conflicting_public_private']} "
              f"dup={c['duplicate_private']} vary_cookie={c['vary_has_cookie']}")

    dest = Path("recon/control_audit.json")
    dest.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n-> {dest}")
    print(f"-> {OUT}/ (raw evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
