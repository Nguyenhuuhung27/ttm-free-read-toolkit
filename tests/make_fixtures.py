#!/usr/bin/env python3
"""Tao lai synthetic fixtures mot cach deterministic.

    python tests/make_fixtures.py

Dung file thay vi `python -c \"...\"` vi bash se expand `$1b` / `$15` thanh
`b` / `5`, lam sai tham chieu RSC. File nay dam bao fixture co the reproduce.

Khong chua noi dung that, cookie, token hay session ID.
"""
from __future__ import annotations

import json
from pathlib import Path

FIX = Path(__file__).resolve().parent / "fixtures"
FIX.mkdir(parents=True, exist_ok=True)

BODY = ("SYNTHETIC-TEST-BODY: doan van tieng Viet co dau de kiem tra UTF-8: "
        "Tiểu Thuyết Mạng, chương thử nghiệm.\r\n"
        "Dong hai cua noi dung gia.\r\n"
        "Dong ba ket thuc.")

PROPS_FREE = ('{"chapterId":"01SYNTHETICFREE0000000000","chapterNumber":1,'
              '"chapterTitle":"Synthetic free","content":"$1b","locked":false}')
PROPS_FREE_RSC = ('{"chapterId":"01SYNTHETICFREE0000000000","chapterNumber":1,'
                  '"chapterTitle":"Synthetic free","content":"$15","locked":false}')
PROPS_LOCKED = ('{"chapterId":"01SYNTHETICLOCKED00000000","chapterNumber":4,'
                '"chapterTitle":"Synthetic locked","content":"","locked":true,'
                '"remainingDailyUnlocks":0}')
TOC = ('{"chapters":[{"chapterNumber":1,"title":"one","hasAudio":true,'
       '"isLocked":false},{"chapterNumber":2,"title":"two","hasAudio":false,'
       '"isLocked":true},{"chapterNumber":3,"title":"three","hasAudio":false,'
       '"isLocked":true}]}')


def push(stream: str) -> str:
    return "<script>self.__next_f.push([1," + json.dumps(stream) + "])</script>"


def main() -> int:
    stream_free = "\n".join([
        '1:HL["/_next/static/media/x.woff2","font",{}]',
        '6:["$","div",null,{"children":[["$","$L1a",null,' + PROPS_FREE + '],'
        '["$","$L1c",null,' + TOC + ']]}]',
        "1b:T16050," + BODY,
        '7:I[3711,[],"ChapterComments"]',
    ])
    (FIX / "free_chapter.html").write_text(
        '<!DOCTYPE html><html><head><title>synthetic</title></head><body>'
        '<div class="prose">' + BODY.replace("\r\n", " ") + '</div>'
        + push(stream_free) + "</body></html>", encoding="utf-8")

    stream_locked = "\n".join([
        '1:HL["/_next/static/media/x.woff2","font",{}]',
        '6:["$","div",null,{"children":[["$","$L1a",null,' + PROPS_LOCKED + ']]}]',
        '1b:I[3711,[],"ChapterComments"]',
    ])
    (FIX / "locked_chapter.html").write_text(
        '<!DOCTYPE html><html><head><title>synthetic</title></head><body>'
        '<div>Chương này đang bị khóa. Đăng nhập để đọc tiếp.</div>'
        + push(stream_locked) + "</body></html>", encoding="utf-8")

    # Moi chunk RSC ket thuc bang newline. Giu newline o cuoi de payload cua
    # chunk `15` co hinh dang giong chunk `1b` trong HTML (co chunk ke tiep).
    (FIX / "free_chapter.rsc").write_text("\n".join([
        '1:HL["/_next/static/media/x.woff2","font",{}]',
        '6:["$","div",null,{"children":[["$","$L1a",null,' + PROPS_FREE_RSC + ']]}]',
        "15:T16050," + BODY,
    ]) + "\n", encoding="utf-8")

    (FIX / "locked_chapter.rsc").write_text("\n".join([
        '1:HL["/_next/static/media/x.woff2","font",{}]',
        '6:["$","div",null,{"children":[["$","$L1a",null,' + PROPS_LOCKED + ']]}]',
        "a:T6f,metadata-only",
    ]), encoding="utf-8")

    (FIX / "toc.html").write_text(
        "<html>" + push('6:["$","$L1c",null,' + TOC + ']') + "</html>",
        encoding="utf-8")

    (FIX / "headers_fixture.json").write_text(json.dumps({
        "public_private_conflict": {
            "Cache-Control": "public, s-maxage=300, private, no-store, max-age=0",
            "Vary": "RSC, Accept-Encoding", "cf-cache-status": "DYNAMIC"},
        "user_scoped_ok": {
            "Cache-Control": "private, no-store, max-age=0, must-revalidate",
            "Vary": "RSC, Accept-Encoding", "cf-cache-status": "DYNAMIC"},
        "cors_safe": {"Access-Control-Allow-Origin": None,
                      "Access-Control-Allow-Credentials": None},
    }, indent=2), encoding="utf-8")

    (FIX / "sessions_fixture.json").write_text(json.dumps({
        "no_sessions": [],
        "a_not_entitled": [
            {"label": "A", "locked": True, "body_chars": 0, "body_sha": "aaa"},
            {"label": "B", "locked": True, "body_chars": 0, "body_sha": "aaa"}],
        "isolated": [
            {"label": "A", "locked": False, "body_chars": 38103, "body_sha": "aaa"},
            {"label": "B", "locked": True, "body_chars": 0, "body_sha": "bbb"}],
        "leak": [
            {"label": "A", "locked": False, "body_chars": 38103, "body_sha": "aaa"},
            {"label": "B", "locked": False, "body_chars": 38103, "body_sha": "aaa"}],
    }, indent=2), encoding="utf-8")

    for f in sorted(FIX.iterdir()):
        print(f.name, f.stat().st_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
