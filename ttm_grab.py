#!/usr/bin/env python3
"""Tai chuong (text) + audio cho tieuthuyetmang.com.

Cơ chế (đo được, xem FINDINGS.md):
  * Mọi route /truyen/* bị access gate (307 -> /khong-co-pass).
    Bypass: thêm hậu tố `.html` vào path.
  * Body chương nằm trong RSC flight stream chunk `1b:`.
  * Chương bị khoá -> `locked: true`, content rỗng -> KHÔNG có body.
  * Audio (`/nghe/<N>.html`) chỉ trả audioUrl khi đủ hạng VIP.

    export TTM_COOKIE='...'
    python ttm_grab.py "<URL>" --from 1 --to 40
    python ttm_grab.py "<URL>" --audio
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

from ttm_recon import (DELAY, ORIGIN, SLUG_RE, UA, chapter_body, flight_stream,
                       http_get, parse_chapters, parse_chapter_props,
                       probe_doc, probe_nghe, strip_rsc_prefix)

MEDIA_RE = re.compile(r"\.(?:mp3|m4a|aac|ogg|wav|m3u8)(?:[?#]|$)", re.I)


def safe(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "-", name).strip()[:120]


def clean(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    return "\n\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--from", dest="start", type=int)
    ap.add_argument("--to", dest="end", type=int)
    ap.add_argument("--audio", action="store_true")
    ap.add_argument("--out", default="download")
    args = ap.parse_args()

    m = SLUG_RE.search(args.url)
    if not m:
        print("URL khong hop le", file=sys.stderr)
        return 2
    slug = m.group(1)
    cookie = os.environ.get("TTM_COOKIE") or None
    if not cookie:
        print("! TTM_COOKIE trong — chi tai duoc phien ban mo (chuong free)", file=sys.stderr)

    root = Path(args.out) / slug
    (root / "text").mkdir(parents=True, exist_ok=True)
    if args.audio:
        (root / "audio").mkdir(parents=True, exist_ok=True)

    # 1) trang chương đầu tiên -> lấy mục lục trong payload
    first = args.start or 1
    rep = probe_doc(slug, first, cookie)
    if rep["status"] != 200:
        print(f"Khong doc duoc trang ch.{first}: HTTP {rep['status']}", file=sys.stderr)
        return 1
    raw = Path("recon") / f"doc_{first}_{'auth' if cookie else 'anon'}.html"
    chapters = parse_chapters(flight_stream(raw.read_text(encoding="utf-8")))
    if not chapters:
        print("Khong thay muc luc trong payload", file=sys.stderr)
        return 1

    picked = [c for c in chapters
              if (args.start is None or c["chapterNumber"] >= args.start)
              and (args.end is None or c["chapterNumber"] <= args.end)]
    print(f"slug={slug}  tong={len(chapters)}  se_xu_li={len(picked)}")

    saved, skipped, gated = 0, [], []
    for c in picked:
        n = c["chapterNumber"]
        title = str(c.get("title") or f"Chuong {n}").strip()
        target = root / "text" / f"{n:05d}-{safe(title)}.md"
        if target.exists():
            print(f"  ch.{n}: da co, bo qua")
            continue

        r = probe_doc(slug, n, cookie)
        if r["verdict"] != "BODY_PRESENT":
            (gated if r["locked_flag"] else skipped).append(n)
            print(f"  ch.{n}: {r['verdict']} (locked={r['locked_flag']})")
            continue

        body = clean(strip_rsc_prefix(chapter_body(
            flight_stream((Path("recon") / f"doc_{n}_{'auth' if cookie else 'anon'}.html")
                         .read_text(encoding="utf-8")))))
        if len(body) < 200:
            skipped.append(n)
            print(f"  ch.{n}: rong")
            continue
        target.write_text(f"# {title}\n\n{body}\n", encoding="utf-8")
        saved += 1
        print(f"  ch.{n}: {len(body)} ky tu -> {target.name}")

        if args.audio and c.get("hasAudio"):
            au = probe_nghe(slug, n, cookie)
            if au["verdict"] == "AUDIO_OK" and au["media"]:
                mp3 = root / "audio" / f"{n:05d}.mp3"
                if not mp3.exists():
                    with requests.get(au["media"],
                                      headers={"User-Agent": UA, "Referer": au["url"]},
                                      timeout=180, stream=True) as resp:
                        resp.raise_for_status()
                        with mp3.open("wb") as fh:
                            for chunk in resp.iter_content(65536):
                                fh.write(chunk)
                    time.sleep(DELAY)
                    print(f"    audio {mp3.stat().st_size} bytes")
            else:
                print(f"    audio: {au['verdict']}")

    print(f"\nDa luu {saved} chuong -> {root}")
    if gated:
        print(f"Khoa (server chan body): {len(gated)} chuong {gated[:20]}")
    if skipped:
        print(f"Rong/loi: {len(skipped)} {skipped[:20]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
