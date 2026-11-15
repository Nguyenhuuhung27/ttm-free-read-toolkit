"""Pure classification helpers used by the TTM audit scripts.

Khong co side effect, khong can network, khong doc file. Chi nhan vao dict/string
da duoc capture hoac synthetic fixture va tra ve nhan phan loai.

Muc dich: tach biet RO RANG 3 trang thai theo yeu cau cua brief:
  - Observed  : co bang chung response cu the (xem `evidence_refs`)
  - Inferred  : dien giai hop ly nhung chua reproduce
  - Unknown   : chua xac lap (vi du: thieu staging / 2 tai khoan test)

Dat tai day de co the unit-test ma khong can goi `requests`.
"""

from __future__ import annotations

import hashlib
import json
import re

OBSERVED = "Observed"
INFERRED = "Inferred"
UNKNOWN = "Unknown"

# Cac dinh dang audio duoc ho tro khi phat hien media reference.
SUPPORTED_AUDIO_EXT = ("mp3", "m4a", "aac", "ogg", "wav", "m3u8")


def content_state(*, locked, body_chars: int, has_audio_url: bool = False) -> str:
    """Phan loai noi dung chương tu field server tra ve.

    QUY TAC (brief rule 6): HTTP status KHONG duoc truyen vao ham nay.
    Status 200 khong bao gio duoc dung de ket luan "co noi dung duoc bao ve".
    """
    if locked is None:
        return UNKNOWN
    if locked and body_chars == 0 and not has_audio_url:
        return "LOCKED_NO_PROTECTED_DATA"
    if locked:
        # Co locked=true ma van co body/audio -> can bao cham, khong tu ket luan exploit.
        return "LOCKED_WITH_DATA_NEEDS_REVIEW"
    if not locked and body_chars > 0:
        return "FREE_CONTENT_PRESENT"
    return "FREE_NO_CONTENT"


def normalize_content(text: str) -> str:
    """Chuan hoa noi dung chuong de fingerprint, doc lap voi metadata dong.

    Dynamic HTML/RSC (timestamp, request id, tracking) thay doi moi request
    nen hash toan response KHONG dung de so sanh giua hai phien. Chuan hoa
    CRLF -> LF, gom khoang trang, rut gon dong trong thua -> noi dung thuc
    su giong nhau moi ra cung mot fingerprint.
    """
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def content_fingerprint(text: str) -> dict:
    """Fingerprint CHI noi dung duoc bao ve, khong phai toan bo response.

    Tra ve {chars, sha256, marker_present}. KHONG tra ve raw text.
    """
    norm = normalize_content(text)
    return {
        "chars": len(norm),
        "sha256": hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16] if norm else None,
    }


def audio_signals(text: str) -> dict:
    """Phat hien SU CO MAT audio trong payload.

    Phat hien CA HAI kieu:
      - thuoc tinh `audioUrl` (co gia tri khac rong / null),
      - media reference tro toi dinh dang audio duoc ho tro.

    KHONG bao gio tra ve hoac luu URL that; chi dem so luong.
    """
    text = text or ""
    # RSC/flight payload la JSON string long trong JS -> dau nhay bi escape
    # (\"audioUrl\"). De do khop ca hai dang, ta tach escape tren ban sao
    # trong bo nho (KHONG luu ban sao nay ra evidence).
    probe = text.replace('\\"', '"')
    prop_present = '"audioUrl"' in probe
    prop_has_value = bool(re.search(r'"audioUrl"\s*:\s*"(?!\s*")', probe))
    media = re.findall(
        r"https?://[^\s\"\\]+\.(?:%s)(?:[^\s\"\\]*)?" % "|".join(SUPPORTED_AUDIO_EXT),
        probe, re.I)
    return {
        "audioUrl_prop_present": prop_present,
        "audioUrl_prop_has_value": prop_has_value,
        "media_ref_present": bool(media),
        "media_ref_count": len(media),
        "media_refs_logged": False,   # URL that KHONG duoc luu
        "has_audio": bool(prop_has_value or media),
    }


def audio_entitlement_state(*, a_has_audio: bool | None,
                            b_has_audio: bool | None,
                            a_entitled: bool | None = None) -> str:
    """Verdict cho WS4 (audio entitlement).

    QUY TAC (brief rule 6):
      - A la tai khoan DUOC entitlement, B la tai khoan KHONG duoc.
      - A (duoc entitlement) ma KHONG co audio -> UNKNOWN. Day la phép thu
        VO NGHI (entitlement co the khong bao gom audio tier), KHONG phai
        ket luan thanh cong.
      - B (KHONG duoc entitlement) ma VAN co audio -> OBSERVED_NEEDS_REVIEW.
      - A co audio va B khong -> OBSERVED_CONSISTENT.
    """
    if a_entitled is False:
        return "UNKNOWN_A_NOT_ENTITLED"
    if a_has_audio is None or b_has_audio is None:
        return "UNKNOWN_MISSING_SIGNAL"
    if not a_has_audio:
        return "UNKNOWN_A_NO_AUDIO"
    if b_has_audio:
        return "OBSERVED_NEEDS_REVIEW"
    return "OBSERVED_CONSISTENT"


def record_fingerprint(raw: bytes) -> dict:
    """Fingerprint mot object record (danh sach) ma KHONG luu noi dung.

    Tra {parsed, count, sha256}. `sha256` la hash cua danh sach sau khi
    canon hoa (sap xep theo chuoi JSON), nen thu tu dong khong anh huong.
    """
    raw = raw or b""
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return {"parsed": False, "count": None,
                "sha256": hashlib.sha256(raw).hexdigest()[:16]}
    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("readingHistory", "comments", "favorites", "items",
                    "data", "results", "history"):
            val = data.get(key)
            if isinstance(val, list):
                items = val
                break
        if items is None:
            items = [{"key": k, "value": v} for k, v in sorted(data.items())]
    canon = json.dumps(sorted(items, key=lambda o: json.dumps(o, sort_keys=True)),
                       sort_keys=True, ensure_ascii=False)
    return {"parsed": True, "count": len(items),
            "sha256": hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]}


def object_authz_state(*, record_created: bool,
                       a_can_read: bool | None = None,
                       b_can_read: bool | None = None,
                       anon_rejected: bool | None = None,
                       b_write_accepted: bool | None = None,
                       a_record_unchanged: bool | None = None) -> str:
    """Verdict cho WS2 (object-level authorization) sau khi co record synthetic.

    - Chua tao duoc record synthetic -> UNKNOWN_NO_SYNTHETIC_RECORD.
    - B DOC duoc record cua A       -> OBSERVED_NEEDS_REVIEW.
    - B SUA duoc record cua A       -> OBSERVED_NEEDS_REVIEW.
    - A doc duoc, B khong, anon bi tu choi -> OBSERVED_ISOLATED.
    - Con lai -> UNKNOWN_INCONCLUSIVE (khong du du lieu de ket luan).
    """
    if not record_created:
        return "UNKNOWN_NO_SYNTHETIC_RECORD"
    if b_can_read:
        return "OBSERVED_NEEDS_REVIEW"
    if b_write_accepted and a_record_unchanged is False:
        return "OBSERVED_NEEDS_REVIEW"
    if a_can_read and anon_rejected is not False:
        return "OBSERVED_ISOLATED"
    return "UNKNOWN_INCONCLUSIVE"


def cache_isolation_state(*, session_rows, cache_hit_seen: bool) -> str:
    """Phan loai ket qua cach ly cache.

    Chi tra ve OBSERVED_CROSS_SESSION_LEAK khi co day du:
      - A co entitlement that (locked=false, body>200), VA
      - B nhan duoc cung noi dung do.
    `content_sha` (fingerprint noi dung) duoc ua tien so voi `body_sha`
    (hash toan response) vi hash toan response bien doi theo metadata dong.
    Khong co 2 phien that -> UNKNOWN, KHONG BAO GIO suy ra tu `Vary`/`Cache-Control`.
    """
    if not session_rows:
        return "UNKNOWN_NO_AUTHORIZED_SESSIONS"
    by_label = {r.get("label"): r for r in session_rows}
    a = by_label.get("A")
    b = by_label.get("B")
    if not a or not b:
        return "UNKNOWN_INCOMPLETE_SESSIONS"
    if a.get("locked") is not False or (a.get("body_chars") or 0) < 200:
        return "UNKNOWN_A_NOT_ENTITLED"
    a_sha = a.get("content_sha") or a.get("body_sha")
    b_sha = b.get("content_sha") or b.get("body_sha")
    if (b.get("body_chars", 0) > 200 and b_sha and a_sha
            and b_sha == a_sha):
        return "OBSERVED_CROSS_SESSION_LEAK"
    return "OBSERVED_ISOLATED"


def classify(claim: str, *, evidence_refs, reproduced: bool,
             prerequisite_missing: str | None = None) -> dict:
    """Tra ve 1 ban ghi phan loai chuan cho moi hypothesis/finding."""
    if prerequisite_missing:
        status = UNKNOWN
    elif reproduced and evidence_refs:
        status = OBSERVED
    elif evidence_refs:
        status = INFERRED
    else:
        status = UNKNOWN
    return {"claim": claim, "status": status,
            "evidence_refs": list(evidence_refs),
            "reproduced": bool(reproduced),
            "prerequisite_missing": prerequisite_missing}


def redact(text: str) -> str:
    """Che gia tri cookie/token trong log. Chi giu ten key + do dai."""
    import re
    text = re.sub(r"(__Host-[A-Za-z0-9._-]+)=([^;,\s]+)",
                  lambda m: f"{m.group(1)}=<redacted:{len(m.group(2))}>", text)
    text = re.sub(r"(__Secure-[A-Za-z0-9._-]+)=([^;,\s]+)",
                  lambda m: f"{m.group(1)}=<redacted:{len(m.group(2))}>", text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{12,}", r"\1<redacted>", text)
    return text
