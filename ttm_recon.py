#!/usr/bin/env python3
"""Recon cho tieuthuyetmang.com — bản cập nhật theo cơ chế site MỚI (2026-11).

Kết quả đo được (không suy đoán):
  * Site bật "access gate" (`/api/config` -> access_gate_enabled=1). Mọi route
    /truyen/* trả 307 -> /khong-co-pass?next=... (form POST /api/access-gate,
    field `key`).
  * BYPASS ĐO ĐƯỢC: thêm hậu tố `.html` vào path -> 200, không còn gate.
    Vd: /truyen/<slug>/doc/26.html
  * Body chương KHÔNG nằm trong HTML render sẵn. Nó nằm trong RSC flight
    stream, ở chunk `1b:` (dạng `1b:T16050,<text>`), chỉ khi chương KHÔNG bị
    khoá. Chương bị khoá -> `content:""`, không có body trong payload.
  * Mục lục (chapters[]: chapterNumber/title/hasAudio/isLocked) nằm ngay trong
    payload của trang /doc/<N>.html -> dùng làm TOC, không cần trang landing.
  * Trang /nghe/<N>.html chỉ trả audioUrl khi người dùng đủ hạng VIP; với
    anonymous server render "Audio bị khóa" -> KHÔNG lấy được URL audio.

Cách dùng:
    export TTM_COOKIE='...'      # optional: cookie phiên của chính bạn
    python ttm_recon.py "https://tieuthuyetmang.com/truyen/<slug>" --sample 3
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ORIGIN = "https://tieuthuyetmang.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
SLUG_RE = re.compile(r"tieuthuyetmang\.com/truyen/([a-z0-9-]+)")
NUM_RE = re.compile(r"/(?:doc|nghe)/(\d+)")
PUSH_RE = re.compile(r'self\.__next_f\.push\(\[1\s*,\s*')
MIN_BODY = 200
DELAY = 2.0
OUT = Path("recon")


def http_get(url: str, cookie: str | None = None) -> requests.Response:
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "vi-VN,vi;q=0.9,en;q=0.8",
        "Referer": ORIGIN + "/",
    }
    if cookie:
        headers["Cookie"] = cookie
    r = requests.get(url, headers=headers, timeout=30, allow_redirects=False)
    time.sleep(DELAY)
    return r


def flight_stream(markup: str) -> str:
    """Ghép các push __next_f lại. Mỗi push là JSON string literal -> raw_decode."""
    dec = json.JSONDecoder()
    out: list[str] = []
    for m in PUSH_RE.finditer(markup):
        i = m.end()
        if i >= len(markup) or markup[i] != '"':
            continue
        try:
            text, _ = dec.raw_decode(markup, i)
        except ValueError:
            continue
        if isinstance(text, str):
            out.append(text)
    return "".join(out)


CHUNK_HEAD_RE = re.compile(r"(?m)^(1[0-9a-f]|[0-9a-f]):")


def iter_chunks(stream: str):
    """Chia flight stream thành các chunk `<id>:<payload>`.

    Payload của chunk body có thể chứa newline thật, nên phải dùng regex
    nhìn về đầu dòng thay vì split dòng đơn giản.
    """
    heads = list(CHUNK_HEAD_RE.finditer(stream))
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(stream)
        yield h.group(1), stream[h.end():end]


def chapter_body(stream: str) -> str:
    """Body chương nằm ở chunk `1b:` trong flight stream (dạng `1b:T16050,<text>`).

    Chunk dạng `1b:I[module,...]` là component, không phải body -> bỏ qua.
    """
    best = ""
    for cid, payload in iter_chunks(stream):
        if cid != "1b" or payload.startswith("I["):
            continue
        if len(payload) > len(best):
            best = payload
    return best


def strip_rsc_prefix(val: str) -> str:
    """Bỏ tiền tố dạng `T16050,` mà Next.js gắn vào chunk text."""
    return re.sub(r"^T[0-9a-f]*,", "", val)


def parse_chapters(stream: str) -> list[dict]:
    """Mục lục: mảng chapters[] trong payload (chapterNumber/title/hasAudio/isLocked)."""
    dec = json.JSONDecoder()
    out: list[dict] = []
    for m in re.finditer(r'"chapters":\[', stream):
        i = m.end() - 1
        try:
            arr, _ = dec.raw_decode(stream, i)
        except ValueError:
            continue
        if isinstance(arr, list):
            for e in arr:
                if isinstance(e, dict) and "chapterNumber" in e:
                    out.append(e)
            if out:
                break
    return out


def parse_chapter_props(stream: str) -> dict:
    """Props của chương đang xem (locked, chapterId, chapterTitle...)."""
    dec = json.JSONDecoder()
    for m in re.finditer(r'"chapterNumber":', stream):
        floor = max(0, m.start() - 2000)
        pos = stream.rfind("{", floor, m.start())
        while pos != -1:
            try:
                obj, _ = dec.raw_decode(stream, pos)
            except ValueError:
                pos = stream.rfind("{", floor, pos)
                continue
            if isinstance(obj, dict) and "locked" in obj and "chapterId" in obj:
                return obj
            pos = stream.rfind("{", floor, pos)
    return {}


def probe_doc(slug: str, number: int, cookie: str | None) -> dict:
    url = f"{ORIGIN}/truyen/{slug}/doc/{number}.html"
    r = http_get(url, cookie)
    (OUT / f"doc_{number}_{'auth' if cookie else 'anon'}.html").write_text(
        r.text, encoding="utf-8")
    stream = flight_stream(r.text)
    raw = chapter_body(stream)
    body = strip_rsc_prefix(raw)
    props = parse_chapter_props(stream)
    locked = bool(props.get("locked"))

    if locked:
        # Khoá nội dung ở TẦNG SERVER: props.locked=true, content rỗng.
        # Đây KHÔNG phải "chưa đọc được vì UI", cũng KHÔNG phải "đã lấy được".
        verdict = "LOCKED_EMPTY"
    elif len(body) >= MIN_BODY:
        # Chương MỞ (isLocked=false): body có trong payload. Không gọi là LEAK —
        # từ "LEAK" dễ bị hiểu nhầm thành "lấy được nội dung VIP".
        verdict = "BODY_PRESENT"
    else:
        verdict = "EMPTY"

    return {
        "number": number, "url": url, "status": r.status_code,
        "with_cookie": bool(cookie), "verdict": verdict,
        "locked_flag": locked, "chapter_id": props.get("chapterId"),
        "title": props.get("chapterTitle"),
        "body_chars": len(body), "excerpt": body[:200],
    }


def probe_nghe(slug: str, number: int, cookie: str | None) -> dict:
    url = f"{ORIGIN}/truyen/{slug}/nghe/{number}.html"
    r = http_get(url, cookie)
    (OUT / f"nghe_{number}_{'auth' if cookie else 'anon'}.html").write_text(
        r.text, encoding="utf-8")
    stream = flight_stream(r.text)
    media = ""
    dec = json.JSONDecoder()
    for m in re.finditer(r'"', stream):
        try:
            val, _ = dec.raw_decode(stream, m.start())
        except ValueError:
            continue
        if isinstance(val, str) and re.search(r"\.(?:mp3|m4a|aac|ogg|wav|m3u8)(?:[?#]|$)", val, re.I):
            media = val.strip()
            break
    res = {"number": number, "url": url, "status": r.status_code,
           "has_audio_prop": '"audioUrl"' in stream, "media": media}
    if "Audio bị khóa" in stream or "nâng cấp" in stream:
        res["verdict"] = "AUDIO_LOCKED"
    elif media:
        res["verdict"] = "AUDIO_OK"
    else:
        res["verdict"] = "NO_AUDIO"
    if media:
        try:
            h = requests.head(media, headers={"User-Agent": UA, "Referer": url},
                              timeout=30, allow_redirects=True)
            res["anon_head"] = h.status_code
            res["content_length"] = h.headers.get("Content-Length")
            res["content_type"] = h.headers.get("Content-Type")
        except requests.RequestException as exc:
            res["anon_head"] = f"error: {exc}"
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--sample", type=int, default=3)
    ap.add_argument("--audio", action="store_true")
    args = ap.parse_args()

    m = SLUG_RE.search(args.url)
    if not m:
        print("Khong lay duoc slug tu URL", file=sys.stderr)
        return 2
    slug = m.group(1)
    cookie = os.environ.get("TTM_COOKIE") or None
    OUT.mkdir(exist_ok=True)

    direct = NUM_RE.search(args.url)
    start = int(direct.group(1)) if direct else 1

    rep = probe_doc(slug, start, cookie)
    stream = flight_stream((OUT / f"doc_{start}_{'auth' if cookie else 'anon'}.html")
                            .read_text(encoding="utf-8"))
    chapters = parse_chapters(stream)

    print(f"slug={slug}  co_cookie={bool(cookie)}  trang={rep['status']}")
    print(f"  muc luc: {len(chapters)} chuong")
    locked = [c for c in chapters if c.get("isLocked")]
    print(f"  khoa={len(locked)}  mo={len(chapters) - len(locked)}")
    print(f"  ch.{start}: {rep['verdict']} locked_flag={rep['locked_flag']} "
          f"body_chars={rep['body_chars']}")
    print(f"  excerpt: {rep['excerpt'][:160]}")

    picked = [c["chapterNumber"] for c in chapters][: args.sample] if not direct else [start]
    report = {"slug": slug, "at": datetime.now(timezone.utc).isoformat(),
              "with_cookie": bool(cookie), "chapters": [], "audio": [],
              "toc_size": len(chapters)}
    for n in picked:
        r = probe_doc(slug, n, cookie)
        report["chapters"].append(r)
        print(f"  ch.{n}: {r['verdict']} body={r['body_chars']} locked={r['locked_flag']}")
        if args.audio:
            au = probe_nghe(slug, n, cookie)
            report["audio"].append(au)
            print(f"    audio: {au['verdict']} media={'co' if au['media'] else 'khong'}")

    (OUT / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n-> {OUT / 'report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
