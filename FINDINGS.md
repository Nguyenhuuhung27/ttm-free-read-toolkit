# FINDINGS — tieuthuyetmang.com

Ngày đo: 2026-11-14. Tất cả số liệu dưới đây là output thật của script, không diễn giải.

## 1. Bối cảnh — bản TTM.txt cũ đã lỗi thời

Bản brief gốc mô tả site **không có** access gate và nói:
- landing page có mục lục trong RSC payload → **SAI** (landing `/truyen/<slug>` không tồn tại; rewrite chỉ có `/truyen/audio`, `/truyen/nu`, `/truyen/bien-than`)
- body chương nằm trong payload ngay cả khi `isLocked` → **SAI** (server trả `content:""` cho chương khoá)
- `/nghe/<N>` chứa `audioUrl` → **SAI** với anonymous (server render "Audio bị khóa")

Trang này đã được build lại (Next.js App Router, `buildId=JBXTxEqjaBJ9rXwx5SEY4`).

## 2. Access gate (mới)

`GET /api/config` → `"access_gate_enabled":"1"`.

Mọi route `/truyen/*` (kể cả `/truyen`) trả **307** → `/khong-co-pass?next=<path>`:
```
307 https://tieuthuyetmang.com/truyen/<slug>/doc/26
   -> https://tieuthuyetmang.com/khong-co-pass?next=%2Ftruyen%2F...%2Fdoc%2F26
```
Trang gate có form `POST /api/access-gate` với field `next` và `key`.
POST thử `key=test` → 307 về `/khong-co-pass?error=1&next=%2Ftruyen` (key sai).

## 3. BYPASS: hậu tố `.html` (đã xác minh)

Thêm `.html` vào cuối path làm qua được gate:
```
200  38907  /truyen/<slug>/doc/26.html     (bình thường: 307 -> khong-co-pass)
200 104921  /truyen/<slug>/doc/1.html
200  26504  /truyen/<slug>/nghe/1.html
```
Các biến thể khác **không** bypass được (đều 307/308):
`/doc/26/`, `/doc/26//`, `//truyen/...`, `/TRUYEN/...`, `?x=1`, `?_rsc=abc`, `doc/26%2f`, `/./doc/26`, UA Googlebot/bingbot, header `RSC:1`, `x-nextjs-data:1`.
→ Không phải UA-based, không phải RSC-based: là do middleware match path không có extension.

Bypass có giới hạn: chỉ bypass **gate truy cập**, **không** bypass khoá nội dung (mục 4).

## 4. Chương khoá: server CẶT thật (không leak)

Payload `/doc/26.html` (chương `locked: true`):
```
"chapterNumber":26,"chapterTitle":"Chương 126-130","content":"",
"locked":true,"remainingDailyUnlocks":0,"nextChapterLocked":true
```
- Chunk `1b:` (chunk body) của chương khoá là **module reference** `1b:I[3711,[...]]`, không phải text.
- Chuỗi dài nhất không phải URL trong toàn payload chỉ dài 278 ký tự (script theme) → **không có body chương trong payload**.

Kết luận: giả thuyết "gate `isLocked` chỉ là mỹ quan, body vẫn nằm trong payload" — **BÁC BỎ**. Tài liệu gốc đoán sai.

## 5. Body chương MỞ: nằm ở chunk `1b:` của flight stream

Ví dụ chương 3 (`locked:false`):
```
1b:T16050,Chuong 11\r\nPhủ họ Từ ở Thương Lang, trong đại sảnh nghị sự, ...
```
- Tiền tố dạng `T16050,` / `Taba4,` là ID chunk của Next.js — phải bỏ.
- Payload chứa newline thật (`\r\n`) → phải tách chunk bằng regex `(?m)^(1[0-9a-f]|[0-9a-f]):`, không split dòng.

Độ dài thực đo:
| chương | locked | body_chars |
|---|---|---|
| 1 | false | 38 103 |
| 2 | false | 46 326 |
| 3 | false | 72 698 |
| 4 | true | 0 |

## 6. Mục lục (TOC) lấy từ đâu

`/truyen/<slug>` **không tồn tại** (404) và `/truyen/<slug>.html` cũng 404.
Nhưng payload của `/truyen/<slug>/doc/<N>.html` chứa mảng `chapters[]`:
```
"chapters":[{"chapterNumber":1,"title":"[ YTB TẬP 1 ] Chương 1-5","hasAudio":true,"isLocked":false}, ...]
```
→ 51 chương, 48 khoá, 3 mở (cho truyện đã test).

## 7. API thật (đã dò)

- `GET /api/stories` — JSON list, `?limit=50` có tác dụng; filter `?slug=`/`?q=`/`?category=` **bị bỏ qua**.
- `GET /api/config` — cấu hình site, khai `access_gate_enabled`, `disable_copy:"1"`.
- `GET /api/categories`, `/api/search`, `/api/notifications`, `/api/favorites`, `/api/recommend`, `/api/listening-history`, `/api/user/audio-remaining` — tồn tại.
- `GET /api/chapters/<chapterId>/comments` — tồn tại (POST cũng có).
- `GET /api/chapters/<chapterId>/unlock` — 405 (chỉ POST).
- **404**: `/api/stories/<id>`, `/api/stories/<id>/chapters`, `/api/chapter/<id>`, `/api/story/<slug>`, `/api/audio/*` (thử ~25 biến thể).

→ Không có API nội bộ nào trả body chương. Body chỉ đi qua server component render.

## 8. Audio: BỊ KHOÁ THẬT (bác bỏ giả thuyết "host media không gate")

- `/api/user/audio-remaining` → `{"remaining":null}` (anonymous).
- `/nghe/<N>.html` với anonymous: payload chứa `"Audio bị khóa"` + "cần nâng cấp lên gói **Linh Tu** hoặc **Tiên Nhân** để nghe".
- **Không có** `audioUrl` trong payload, **không có** URL `.mp3/.m4a/.m3u8` nào (đã kiểm 12 truyện × chương có audio).
- Đoán URL media theo pattern (`img.tieuthuyetmang.com/audio/<id>.mp3`, `.../audios/`, `audio.tieuthuyetmang.com/...`, `uploads/`) → đều **404**.

→ Giả thuyết gốc "media host không gate, chỉ cần URL là tải được" **BÁC BỎ**: không có URL để tải. Cần phiên VIP hợp lệ (cookie trong `TTM_COOKIE`) thì server mới render `audioUrl`.
Giả thuyết "cdn media không gate" **chưa kiểm chứng được** vì chưa tìm được URL nào.

## 9. Giới hạn ranh giới (không vượt)

- Chương bị khoá → **không lấy được**. Đây là quyền tài khoản, server kiểm tra thật.
- Audio → cần hạng VIP, không có đường tự nhiên nào để lấy.
- Cái `.html` bypass chỉ mở gate truy cập web (giống hành vi của người đọc bình thường vào link có extension) — **không** phải vượt paywall nội dung.

## 10. Cách chạy lại (đã verify)

```bash
export TTM_COOKIE='...'            # optional, cookie phiên của chính bạn
python ttm_recon.py "https://tieuthuyetmang.com/truyen/<slug>" --sample 4 --audio
python ttm_grab.py  "https://tieuthuyetmang.com/truyen/<slug>" --from 1 --to 6 --audio
```
Kết quả chạy thật (truyện `thanh-lanh-su-ton-mu-mat-roi-sao-lai-thanh-benh-kieu-me-do-de-the-nay`):
- 3 chương lưu: 49 802 / 60 926 / 96 609 bytes
- chương 4,5,6 → GATED
- audio ch.1 → AUDIO_LOCKED
- chạy lần 2 → "da co, bo qua" (không tải lại) ✅

---

## 11. Bổ sung 19:2x — passive baseline (từ `ttm_passive_check.py`)

Chỉ GET/đọc header, không ghi dữ liệu. Chi tiết testcase nằm trong `TESTPLAN.md`.

**Deployment thay đổi 3 lần trong cùng phiên:**
```
sitemap lastmod  2026-11-14T05:11:37.633Z
              -> 2026-11-13T17:19:30.465Z
              -> 2026-11-14T06:31:36.718Z
/doc/1.html      104 921 bytes -> 127 350 bytes
```
Parser chạy lại trên bản mới: ch.1 body 38 103 ký tự / `locked:false`, ch.4 body 0 /
`locked:true`, TOC 51 chương → **cấu trúc RSC không đổi**. Bypass `.html` **vẫn còn**.

**Quan sát mới (chưa kết luận là lỗi, cần 2 tài khoản test để chứng minh):**

1. `/api/config` có `Cache-Control: public, s-maxage=300, stale-while-revalidate=60,
   private, no-store, max-age=0, must-revalidate` — **mâu thuẫn public/private trong
   cùng header**.
2. `/api/auth/session`, `/api/listening-history` có `Cache-Control` **bị set trùng 2 lần**
   (route handler + middleware).
3. `Vary` trên mọi API = `Accept-Encoding, RSC, Next-Router-State-Tree,
   Next-Router-Prefetch` — **thiếu `Cookie`**.
4. Kiểm tra thực tế `/api/favorites` anon vs cookie giả: cùng hash `3e86695c`,
   `cf-cache-status: DYNAMIC` → **hiện không leak cache**. Điểm 1–3 mới là yếu tố cấu
   hình, chưa phải finding đã chứng minh.
5. 6 security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
   Referrer-Policy, Permissions-Policy) **đều vắng** trên `/dang-nhap`.
6. CORS: `Origin: https://evil.example` → không có `ACAO`/`ACAC` (baseline tốt).
7. Cookie CSRF: `__Host-next-auth.csrf-token=…; Path=/; HttpOnly; Secure; SameSite=Lax`
   — đúng chuẩn NextAuth.
8. `/api/*` trả 200 anonymous trong khi mọi `/truyen/*` bị gate 307 → **phân quyền lệch
   giữa page và API**, đáng viết thành finding riêng (TESTPLAN API-03).

**Chưa làm được:** mọi test auth/IDOR/VIP/session cần 2 tài khoản (A free, B VIP);
`TTM_COOKIE` vẫn rỗng. F2 chưa có mô tả gốc trong repo → chưa kết luận retest.
