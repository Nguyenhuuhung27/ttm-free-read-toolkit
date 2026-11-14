#!/usr/bin/env python3
"""Do lai baseline thụ động cho TESTPLAN.md — CHỈ GET, không ghi dữ liệu.

    python ttm_passive_check.py
    TTM_COOKIE_A=... TTM_COOKIE_B=... python ttm_passive_check.py --sessions

Không log giá trị cookie/token: chỉ in 8 ký tự đầu của SHA-256 để phân biệt phiên.
1 luồng, nghỉ 2s/request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone

import requests

ORIGIN = "https://tieuthuyetmang.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
DELAY = 2.0
SEC_HEADERS = ("Strict-Transport-Security", "Content-Security-Policy",
               "X-Frame-Options", "X-Content-Type-Options",
               "Referrer-Policy", "Permissions-Policy")
API_PATHS = ("/api/config", "/api/stories", "/api/auth/session", "/api/auth/csrf",
             "/api/favorites", "/api/notifications", "/api/user/audio-remaining",
             "/api/listening-history")
SAMPLE_SLUG = "thanh-lanh-su-ton-mu-mat-roi-sao-lai-thanh-benh-kieu-me-do-de-the-nay"


def fp(cookie: str | None) -> str:
    return "-" if not cookie else hashlib.sha256(cookie.encode()).hexdigest()[:8]


def get(url: str, cookie: str | None = None, extra: dict | None = None) -> requests.Response:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if extra:
        h.update(extra)
    if cookie:
        h["Cookie"] = cookie
    r = requests.get(url, headers=h, timeout=25, allow_redirects=False)
    time.sleep(DELAY)
    return r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", action="store_true",
                    help="them 2 phien tu env TTM_COOKIE_A / TTM_COOKIE_B de so sanh cache")
    ap.add_argument("--out", default="recon/passive_check.json")
    args = ap.parse_args()

    out = {"at": datetime.now(timezone.utc).isoformat(), "origin": ORIGIN,
           "api": [], "security_headers": {}, "cors": [], "cache": [],
           "gate_retest": [], "deployment": {}}

    print("=== API headers ===")
    for p in API_PATHS:
        r = get(ORIGIN + p, extra={"Origin": "https://evil.example"})
        rec = {"path": p, "status": r.status_code,
               "cache_control": r.headers.get("Cache-Control"),
               "vary": r.headers.get("Vary"),
               "cf_cache_status": r.headers.get("cf-cache-status"),
               "acao": r.headers.get("Access-Control-Allow-Origin"),
               "body_len": len(r.content),
               "body_sha256_8": hashlib.sha256(r.content).hexdigest()[:8]}
        out["api"].append(rec)
        print(f"  {p:32} {r.status_code} cache={rec['cache_control']}")

    print("=== Security headers (/dang-nhap) ===")
    r = get(ORIGIN + "/dang-nhap")
    for k in SEC_HEADERS:
        out["security_headers"][k] = r.headers.get(k)
        print(f"  {k:28} {r.headers.get(k) or '-'}")

    print("=== CORS (Origin la) ===")
    for p in ("/api/config", "/api/favorites"):
        r = get(ORIGIN + p, extra={"Origin": "https://evil.example"})
        rec = {"path": p, "acao": r.headers.get("Access-Control-Allow-Origin"),
               "acac": r.headers.get("Access-Control-Allow-Credentials")}
        out["cors"].append(rec)
        print(f"  {p:32} ACAO={rec['acao']}")

    print("=== Cache isolation (anon vs cookie gia) ===")
    a = get(ORIGIN + "/api/favorites")
    b = get(ORIGIN + "/api/favorites", cookie="__Host-next-auth.csrf-token=probe|probe")
    out["cache"] = [
        {"label": "anon", "status": a.status_code, "body": a.text[:120],
         "hash": hashlib.sha256(a.content).hexdigest()[:8]},
        {"label": "fake_cookie", "status": b.status_code, "body": b.text[:120],
         "hash": hashlib.sha256(b.content).hexdigest()[:8],
         "vary_has_cookie": "Cookie" in (b.headers.get("Vary") or ""),
         "cf_cache_status": b.headers.get("cf-cache-status")},
    ]
    for c in out["cache"]:
        print(f"  {c['label']:12} {c['status']} {c['hash']} {c['body'][:40]}")

    if args.sessions:
        print("=== So sanh 2 phien that (CCH-01) ===")
        ca, cb = os.environ.get("TTM_COOKIE_A"), os.environ.get("TTM_COOKIE_B")
        for label, ck in (("A", ca), ("B", cb)):
            if not ck:
                print(f"  {label}: thieu cookie, bo qua")
                continue
            r = get(ORIGIN + "/api/favorites", cookie=ck)
            print(f"  {label} fp={fp(ck)} {r.status_code} len={len(r.content)} "
                  f"hash={hashlib.sha256(r.content).hexdigest()[:8]}")
            out.setdefault("session_compare", []).append(
                {"label": label, "cookie_fp": fp(ck), "status": r.status_code,
                 "body_len": len(r.content),
                 "body_sha256_8": hashlib.sha256(r.content).hexdigest()[:8],
                 "cf_cache_status": r.headers.get("cf-cache-status")})

    print("=== Retest gate .html ===")
    for suffix in ("", ".html"):
        p = f"/truyen/{SAMPLE_SLUG}/doc/1{suffix}"
        r = get(ORIGIN + p)
        rec = {"path": p, "status": r.status_code,
               "location": r.headers.get("Location"), "body_len": len(r.content)}
        out["gate_retest"].append(rec)
        print(f"  {p[-30:]:32} {r.status_code} {rec['body_len']}")

    print("=== Deployment fingerprint ===")
    cfg = get(ORIGIN + "/api/config")
    sm = get(ORIGIN + "/sitemap.xml")
    out["deployment"] = {
        "sitemap_lastmod": re.findall(r"<lastmod>(.*?)</lastmod>", sm.text)[:2],
        "access_gate_enabled": "access_gate_enabled" in cfg.text,
        "gate_flag_value": (json.loads(cfg.text).get("site", {})
                            .get("access_gate_enabled") if cfg.ok else None),
    }
    print(" ", out["deployment"])

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print(f"\n-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
