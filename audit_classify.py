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

OBSERVED = "Observed"
INFERRED = "Inferred"
UNKNOWN = "Unknown"


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


def cache_isolation_state(*, session_rows, cache_hit_seen: bool) -> str:
    """Phan loai ket qua cach ly cache.

    Chi tra ve OBSERVED_LEAK khi co day du:
      - A co entitlement that (locked=false, body>200), VA
      - B nhan duoc cung body do (hash trung A).
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
    if b.get("body_chars", 0) > 200 and b.get("body_sha") == a.get("body_sha"):
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
