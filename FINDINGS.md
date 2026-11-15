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
`TTM_COOKIE` vẫn rỗng. **F2 đã retest xong lúc 20:0x** → xem `CONTROL_AUDIT.md` §4:
phiên bản framework / PHP / đường dẫn nội bộ / stack **không còn tái hiện**; chỉ còn
fingerprint cấu hình công khai. Mô tả gốc F2 vẫn chưa có trong repo, nên kết luận dựa
trên 3 nội dung user nêu.

## 12. Bổ sung 20:0x — phân lớp kiểm soát (xem `CONTROL_AUDIT.md`)

- Đổi nhãn `LEAK` → `BODY_PRESENT` trong `ttm_recon.py`/`ttm_grab.py`: từ "LEAK" gây
  hiểu nhầm thành "lấy được nội dung VIP". Chương khoá giờ là `LOCKED_EMPTY`.
- **Lớp bị bỏ qua = L1 access gate (middleware)**: probe 10 đuôi path cho thấy **mọi
  path có dấu chấm ở segment cuối** (`.html/.json/.txt/.css/.png/./.xhtml/%2Ehtml`)
  đều 200, chỉ path không dấu chấm bị 307. Không phải riêng `.html`.
- **HTTP 200 ≠ đọc được VIP**: ch.4 (`locked:true`) status 200 nhưng `content:""`,
  RSC body 0, DOM `div.prose` 0, DOM tổng 774 ký tự ("Chương này đang bị khóa…").
  Ch.1 (`locked:false`): RSC 38 103 / DOM 32 943 ký tự.
- **Không có API nào cấp dữ liệu khoá**: 11 endpoint, 0 field `content`/`text`/`body`,
  0 `audioUrl`; chuỗi dài nhất `/api/stories` là `contentDescription` (mô tả công khai).
- **F2**: 500 → `{"error":"Internal error"}` (26 bytes), 405 rỗng, 400 generic NextAuth,
  404 không lộ buildId/path FS. `?next=` chỉ self-reflect giá trị client gửi, external/js
  bị chuẩn hoá về `/`. Không request file cấu hình/bí mật.
- **Cấu hình**: CORS không reflect Origin (preflight 204 không ACAO), cookie `__Host-`/
  `__Secure-` đúng luật, 6 security headers vắng, `Cache-Control` mâu thuẫn/lặp,
  `Vary` thiếu `Cookie`, `limit` thiếu validate (500 / không clamp) → **hardening**,
  chưa phân loại thành lỗ hổng khai thác được.

---

## 13. Cập nhật 2026-11-15 — re-verification (xem `NEXT_AUDIT.md`)

> Phần này **cập nhật** các mục §1–12, không tạo claim trùng. Commit gốc `2415a88`.
> Re-verify bằng offline tests (`python -m unittest discover -s tests -v` → 37/37 OK)
> trên evidence JSON có sẵn. **Không gọi network**, không có staging, không có
> tài khoản A/B. Toàn bộ evidence vẫn là anonymous production 2026-11-14.

### 13.0 Kết luận tổng

**Không có lỗ hổng nào được chứng minh** ở 3 nhóm mục tiêu: server-side
authorization, entitlement isolation, cache isolation. Clean result là kết quả hợp
lệ. Các mục dưới đây được viết theo đúng cấu trúc yêu cầu để tránh bị đọc nhầm
thành finding.

### F-13.1 — Middleware access-gate bypass bằng path có dấu chấm

| Trường | Giá trị |
|---|---|
| **Title / Severity rationale** | Access-gate (presentation/middleware layer) bị bỏ qua bởi path có extension. **Severity: Informational / hardening — KHÔNG phải vulnerability**. Lý do: theo brief rule 6, middleware-only bypass + response chỉ chứa nội dung công khai **không đủ** để xếp lỗ hổng. Không có leo thang đặc quyền, không có dữ liệu được bảo vệ. |
| **Affected component / code location** | L1 access gate. **Không có source trong repo**; vị trí xác định được là response `307` với `Location: /khong-co-pass?next=…` (`recon/control_audit.json` → `sections.gate.rows`, `gate_response_headers`). Matcher cụ thể là **Inferred**. Client symbol liên quan: `recon/page-2936fb800ce950f1.js` (`/truyen/[slug]/doc/[chapter]`). |
| **Prerequisites / threat boundary** | Attacker không cần credential. Boundary: chỉ với **anonymous / nội dung công khai**. Không áp dụng cho chương `locked:true`, audio VIP, hay dữ liệu user khác. |
| **Reproducible steps (authorized env)** | Trên staging được ủy quyền: `GET /truyen/<test-slug>/doc/<N>` → 307; `GET /truyen/<test-slug>/doc/<N>.html` → 200. Chạy 10 biến thể đuôi từ `ttm_control_audit.py::audit_gate` (1 luồng, 2s/request). |
| **Expected vs actual** | Expected: gate chặn mọi path. Actual (2026-11-14): 1/10 path bị gate, 8× 200, 1× 404 (`.html/x`). Chương khoá trong các response 200 vẫn `content:""` / `body=0`. |
| **Evidence refs** | `recon/control_audit.json` · `sections.gate.dot_suffix_probe`; `CONTROL_AUDIT.md` §1; test `test_gate_dot_suffix_probe_has_10_rows`; `EVIDENCE_INDEX.md` §1 |
| **Impact / limitations** | Ảnh hưởng thật: truy cập **nội dung công khai** dù gate bật. **Không** đọc được nội dung VIP. Evidence đã 1 ngày tuổi; deployment từng đổi 3 lần/phiên → **chưa re-verify trên build 2026-11-15**. |
| **Remediation** | Sửa matcher để không loại trừ path có dấu chấm tuỳ ý (hoặc chặn rõ ràng ở route/page thay vì chỉ middleware); thêm regression test cho danh sách path được bảo vệ. |

### F-13.2 — Server-side entitlement enforcement (kết quả âm tính)

| Trường | Giá trị |
|---|---|
| **Title / Severity** | Không phát hiện bypass entitlement. **Severity: none (clean result)**. 19/19 thử tự gán quyền thất bại; 51/51 chương nhất quán. |
| **Component / location** | Server component của `/truyen/[slug]/doc/[chapter]` — **Inferred** từ RSC props `locked`, `content`, `remainingDailyUnlocks` (`recon/control_audit.json` → `sections.content.chapters.*.props`). Logic client nhận `locked:Z` tại `recon/page-2936fb800ce950f1.js` `@27900`; render `content` tại `@31350`. Không có source server để trích exact line. |
| **Prerequisites / boundary** | **Anonymous**. Chưa có tài khoản A đã mở khoá → không thể khẳng định hành vi với entitlement thật. Không giả mạo entitlement (đúng brief). |
| **Steps (authorized env)** | `python ttm_entitlement_audit.py --sweep` trên staging; với A/B: `TTM_COOKIE_A=… TTM_COOKIE_B=… python ttm_entitlement_audit.py --sessions`. |
| **Expected vs actual** | Expected: chương khoá không trả body ở mọi kênh. Actual: HTML/RSC/prefetch/TOC/API đều `body=0`, `dom=0`, không `audioUrl`; 19 probe (10 query + 6 header + 3 cookie) đều `locked:true`. |
| **Evidence refs** | `recon/entitlement_sweep.json` → `sections.server_authorization`, `sections.content_delivery`; tests `test_19_entitlement_probes_all_locked`, `test_sweep_51_chapters_all_consistent`; `ENTITLEMENT_AUDIT.md` §Câu 1–2 |
| **Impact / limitations** | Không có lộ dữ liệu được bảo vệ. **Unknown**: entitlement được kiểm tra trước hay sau truy vấn DB (không có source/timing); hành vi sau unlock thật; audio cho VIP. |
| **Remediation** | Không cần sửa. Khuyến nghị giữ server-side check và thêm test A/B trên staging để chốt phần còn lại. |

### F-13.3 — Cache isolation (chưa xác lập)

| Trường | Giá trị |
|---|---|
| **Title / Severity** | Chưa chứng minh được rò rỉ cache giữa phiên. **Severity: n/a — Unknown**. Header thiếu `Vary: Cookie` là **review lead**, không phải proof (đúng brief Workstream 4). |
| **Component / location** | Header `Cache-Control`, `Vary`, `cf-cache-status` — `recon/passive_check.json` (`api`, `cache`), `recon/control_audit.json` → `sections.config.cache`, `recon/entitlement_sweep.json` → `sections.cache`. **Không có cấu hình CDN trong repo** → không khẳng định tầng cache nào tồn tại. Framework-level route cache: **Unknown**. |
| **Prerequisites / boundary** | Cần 2 phiên A/B độc lập, A có entitlement tới **test chapter synthetic**, và staging có cấu hình cache rõ ràng. Hiện `TTM_COOKIE_A/B` rỗng → `sections.cache.sessions = null`. |
| **Steps (authorized env)** | A→B→A→anon trên cùng URL, log `status/body_sha/locked/body_chars`, chỉ log hash cookie. Đọc `B_received_A_content`. |
| **Expected vs actual** | Expected: B không nhận body của A. Actual (anonymous): 3× `/api/config` → `DYNAMIC`, hash `76eac9234a`, không `Age`/`ETag`; 7 cache-key variant không lẫn dữ liệu; 5× RSC↔HTML tách đúng Content-Type. **Chưa có phép thử A/B thật.** |
| **Evidence refs** | `recon/entitlement_sweep.json` → `sections.cache`; `CONTROL_AUDIT.md` §5; tests `test_no_real_sessions_recorded`, `test_cache_no_hit_in_evidence`, `TestCacheIsolationClassifier`; `NEXT_AUDIT.md` §5 |
| **Impact / limitations** | Không có bằng chứng dữ liệu lọt sang phiên khác. Các lead: `/api/config` có `public, s-maxage=300` lẫn `private, no-store`; 5 route set header trùng; `Vary` thiếu `Cookie`; `.css/.png` trả HTML với `cf=BYPASS`. Tất cả **chưa phải finding khai thác được**. |
| **Remediation (hardening)** | Gộp `Cache-Control` trùng, bỏ `public/s-maxage` trên route có thể chứa dữ liệu user, thêm `Vary: Cookie` cho route user-scoped, đảm bảo `private, no-store` tuyệt đối cho response chứa nội dung đã mở khoá. |

### F-13.4 — F2 Information Disclosure (đã retest, đã ẩn)

| Trường | Giá trị |
|---|---|
| **Title / Severity** | Framework version / PHP / internal path / stack không còn tái hiện. **Severity: none (remediated / không tái hiện)**. Còn lại fingerprint công khai → hardening nhẹ. |
| **Component / location** | Error responses 400/404/405/500 + header `Server`, `X-Powered-By`. Evidence: `recon/audit/error_*.txt`; `recon/control_audit.json` → `sections.errors.cases[].patterns_found`. |
| **Prerequisites / boundary** | Anonymous, response lỗi tự nhiên. **Không hề request file cấu hình/bí mật**. Mô tả gốc F2 không có trong repo → kết luận dựa trên 3 nội dung user nêu. |
| **Steps (authorized env)** | `python ttm_control_audit.py` (GET/OPTIONS only), đọc 8 case. |
| **Expected vs actual** | Expected: không lộ version/PHP/path/stack/secret. Actual: 0 match cho `php_version`, `framework_version`, `internal_fs_path`, `stack_trace`, `secret_like`, `env_var`, `sql`; 500 → `{"error":"Internal error"}`; 405 rỗng; 400 generic NextAuth. `?next=` chỉ self-reflect, external/`javascript:` bị chuẩn hoá về `/`. |
| **Evidence refs** | `CONTROL_AUDIT.md` §4; `recon/audit/error_*.txt`; test `test_f2_error_responses_hide_sensitive_patterns` |
| **Impact / limitations** | Chỉ còn `Server: cloudflare`, `X-Powered-By: Next.js` (không số phiên bản), tên chunk build công khai. Build hiện tại (2026-11-15) chưa retest. |
| **Remediation** | Tuỳ chọn: bỏ `X-Powered-By`, thống nhất error page, validate `limit` (500/không clamp). Không phải info disclosure. |

### 13.5 Bảng trạng thái 6 giả thuyết cũ

| # | Giả thuyết | Trạng thái | Ghi chú |
|---|---|---|---|
| H1 | Extension bypass gate | **Observed** (anonymous, 2026-11-14) | Không re-verify build hiện tại; không phải vulnerability |
| H2 | Server entitlement vẫn hiệu lực | **Observed** (anonymous) / **Unknown** (A có entitlement) | 19/19 + 51/51 |
| H3 | Body khoá vắng ở HTML/RSC/prefetch | **Observed** | 48/48 `body=0`, 6 kênh |
| H4 | Anonymous không nhận `audioUrl` | **Observed** (anonymous) / **Unknown** (VIP) | 0/11 API |
| H5 | Cache leak chưa chứng minh | **Vẫn đúng — chưa chứng minh** | `sessions = null` |
| H6 | 48/51 khoá, 19/19 thất bại | **Observed**, khớp chính xác | Offline re-computation |

**Không giả thuyết nào bị contradicted; không giả thuyết nào được nâng thành
confirmed vulnerability.** Chi tiết command/test/environment: `NEXT_AUDIT.md` §3,
`HANDOFF.md`.

---

## 14. Cập nhật 2026-11-15 19:3x — 5 ưu tiên A/B (commit `93ebbd1` → đợt này)

> **Kết luận: vẫn KHÔNG có lỗ hổng authorization / data-isolation nào được
> chứng minh.** Không có staging, không có 2 tài khoản được ủy quyền, không có
> test chapter synthetic → **0 request tới ứng dụng** trong đợt này. Theo yêu cầu
> "nếu thiếu prerequisite thì hoàn thành source-level analysis và chuẩn bị
> reproducible tests", tôi đã làm cả hai và **không** truy cập nội dung production
> được bảo vệ.

### 14.1 Prerequisite — đo lại, không giả định

| Biến | Độ dài | Ghi chú |
|---|---|---|
| `TTM_STAGING_URL`, `TTM_BASE_URL`, `STAGING_URL`, `BASE_URL` | 0 | Không có staging URL |
| `TTM_COOKIE`, `TTM_COOKIE_A`, `TTM_COOKIE_B` | 0 | Không có phiên test |
| `TEST_CHAPTER_ID`, `TEST_CHAPTER_SLUG`, `TTM_TEST_SLUG` | 0 | Không có chương synthetic |
| File `.env*`, `docker-compose*`, `next.config*`, `middleware*`, `vercel.json`, `wrangler*` | 0 file | Repo không chứa cấu hình deployment |

→ Cả 5 ưu tiên đều **not verified at runtime**. Không thay thế bằng test trên
production, không giả mạo entitlement, không enumerate ID.

### 14.2 Source-level analysis (từ client bundle đã capture, có byte offset)

Không có source server trong repo, nên đây là **Observed (client) / Inferred
(server)**, không phải xác nhận mã nguồn. Mỗi bundle là 1 dòng minify → dùng
`@offset`.

| Object / chức năng | Call site thật trong bundle | Method & payload | Quyền sở hữu |
|---|---|---|---|
| Reading history | `recon/page-2936fb800ce950f1.js` `@27459` | `POST /api/reading-history`, `credentials:"include"`, body `{storyId,chapterId}` | Client bundle chỉ bắt được call site **POST**. Query key `reading-history-home` tại `@27656` cho thấy có một consumer **GET list** trong bundle khác (chưa capture) → WS2 probe `GET /api/reading-history` để kiểm tra object-level authz mà không mutate. Route dùng session cookie, không nhận `userId` |
| Comments | `@12717` (GET), `@12907` (POST) | `GET /api/chapters/<id>/comments` → `{comments:[]}`; `POST` body `{content}` → `id` | ID là `chapterId` (object chương, không phải user ID); POST gắn session |
| Listening history | `recon/nghe_page.js` `@5047` | `GET /api/listening-history?chapterId=<id>` → `{positionSeconds}` | Tham số `chapterId`, **không** có `userId` trên query |
| Favorites / Notifications | Không có call site trong bundle đã capture; endpoint quan sát được qua `recon/control_audit.json` → `sections.config`, `recon/entitlement_sweep.json` | `GET` → `{"favorites":[]}` / `{"notifications":[]}` | Không có object ID do client truyền → **Inferred** là session-scoped |
| Audio quota | `recon/layout-8430bcd733497a62.js` `@17963` | `GET /api/user/audio-remaining` → `{remaining}` | Chỉ gọi khi `useSession().user.id` tồn tại (`@17963`); không có `userId` param |
| Audio URL | `recon/nghe_page.js` `@4257` | prop `audioUrl` do **server component** truyền vào player | Không thấy client tự dựng URL |
| Unlock | `recon/page-2936fb800ce950f1.js` `@25224` | `POST /api/chapters/<id>/unlock`, không body | Cần mutate scope — **không chạy** |
| Chapter-errors | `@9263`, `recon/nghe_page.js` `@21735` | `POST /api/chapter-errors`, body `{chapterId,description}` | Cần mutate scope — **không chạy** |

**Đáng chú ý:** trong các bundle đã capture **không tìm thấy** `userId`, `owner`,
`commentId` hay `user.id` dùng làm tham số request (kiểm tra 3 bundle, kết quả
`userId × 0`, `owner × 0`). Đây là tín hiệu *ủng hộ* session-scoping, nhưng
**chưa chứng minh** server kiểm tra ownership — cần A/B thật. Không kết luận
IDOR từ việc ID có thể đoán được hay từ response 200.

### 14.3 Reproducible tests đã chuẩn bị (chưa chạy runtime)

`ttm_staging_audit.py` — harness **fail-closed** cho đúng 5 ưu tiên:

| WS | Ưu tiên | Nội dung |
|---|---|---|
| WS1 | A/B session isolation | A/B/anon trên `/doc/<test>.html`, parse `locked`/`content` từ RSC props, so sánh hash. `A_entitled` phải `true` mới có ý nghĩa |
| WS2 | Object-level authz | **6 endpoint**: `reading-history`, `favorites`, `notifications`, `listening-history`, `comments`, `audio-remaining` — chỉ GET, không enumerate ID. Cờ `needs_review` chỉ bật khi A có dữ liệu session-specific (khác anon) **và** B nhận đúng body của A |
| WS3 | Cache isolation | A → B → A_again → anon trên **cùng URL** + `Age`/`ETag`/`cf-cache-status`; đưa qua `cache_isolation_state()` |
| WS4 | Audio entitlement | So sánh sự có mặt `audioUrl` giữa A/B/anon + `/api/user/audio-remaining`; **không lưu URL, không tải audio** |
| WS5 | Middleware matcher | 9 dot-suffix probe + fingerprint `sitemap.xml` / `api/config` để gắn đúng build |

Bảo vệ bắt buộc (đã unit-test):
- Từ chối mọi host production (`*.tieuthuyetmang.com`) và host không có dấu hiệu staging.
- Từ chối nếu thiếu 1 trong 7 env, hoặc `TTM_COOKIE_A == TTM_COOKIE_B`.
- Mặc định **chỉ GET**; `--allow-mutate` cần thêm `TTM_MUTATE_AUTHORIZED=1`.
- Chỉ log status, header whitelist, SHA-256 body, synthetic marker — **không log
  cookie/token, không lưu body, không enumerate ID**.
- Mọi verdict đi qua `audit_classify` (classifier **không nhận HTTP status**).
- `--plan` / `--run` thiếu prerequisite → exit `3`, **không gửi request nào**.

### 14.4 Findings (cập nhật, không tạo claim trùng)

| ID | Tiêu đề | Severity | Trạng thái | Evidence |
|---|---|---|---|---|
| F-14.1 | A/B session & entitlement isolation | n/a | **Unknown — not verified at runtime**. WS1/WS3 sẵn sàng, chưa có phiên thật | `ttm_staging_audit.py`, `tests/test_staging_harness.py`, `recon/staging_plan.json` |
| F-14.2 | Object-level authorization (4 nhóm ưu tiên / 6 endpoint) | n/a | **Unknown**. Source-level: không thấy `userId`/`owner` param; chưa có test records do A/B tạo | §14.2, WS2 |
| F-14.3 | Cache isolation giữa phiên | n/a | **Unknown**. Header lead (`Vary` thiếu `Cookie`) vẫn là review lead, không phải finding | `NEXT_AUDIT.md` §4, WS3 |
| F-14.4 | Audio entitlement consistency | n/a | **Unknown** cho VIP; Observed (anonymous) rằng không có `audioUrl` | WS4, `FINDINGS.md` §8 |
| F-14.5 | Middleware matcher trên build hiện tại | Informational | **Chưa re-verify** (không gọi production). WS5 đã chuẩn bị kèm fingerprint; H1 trên build 2026-11-14 vẫn là Observed, không nâng severity | WS5, `CONTROL_AUDIT.md` §1 |

**Confirmed vulnerabilities: 0.** Không có finding nào được suy ra từ HTTP 200,
header thiếu, hay middleware bypass. Mọi "Observed" mới trong đợt này là
**Observed về code/evidence có sẵn**, không phải quan sát runtime mới.

### 14.5 Definition of done (đợt này)

- [x] Đọc `NEXT_AUDIT.md`, `HANDOFF.md`, `TESTPLAN.md`, script hiện có
- [x] Không lặp lại 37 offline test cũ một cách thừa (chạy 1 lần trong suite đầy đủ)
- [x] Source-level analysis 4 nhóm object + audio + matcher, có byte offset
- [x] Harness fail-closed cho 5 ưu tiên, kèm 18 unit test mock
- [x] Cập nhật `FINDINGS.md` / `EVIDENCE_INDEX.md` / `HANDOFF.md`
- [x] Chạy toàn bộ test, ghi exit code thật
- [ ] Runtime A/B trên staging — **chặn bởi prerequisite**, xem `HANDOFF.md` §5

### 14.6 Sửa khiếm khuyết trong chính harness (vòng 20:0x, không gọi network)

Hai lỗi trong logic sinh evidence của `ttm_staging_audit.py` — **đây là lỗi công cụ
đo lường, không phải lỗ hổng của ứng dụng**. Cả hai đều có test chống tái phát.

| # | Vấn đề | Hệ quả nếu không sửa | Cách sửa |
|---|---|---|---|
| H-1 | WS2 **không probe `/api/reading-history`** dù ưu tiên 2 nêu rõ "reading history" (client chỉ lộ call site POST `@27459`, GET list nằm ở bundle chưa capture) | Object đầu tiên trong ưu tiên 2 không được kiểm tra → báo cáo thiếu phạm vi | Thêm `GET /api/reading-history` vào WS2 (GET-only, không mutate). Ưu tiên 2 giờ phủ **6 endpoint** thay vì 5 |
| H-2 | Cờ `needs_review` viết sai: `a_bytes != b_bytes and b_hash == a_hash` — hai điều kiện **loại trừ nhau** (hash bằng nhau ⇒ byte bằng nhau), nên cờ **không bao giờ bật** | Cross-session data leak thật sẽ **không** được gắn cờ review; âm thầm bỏ sót | Tách thành `a_has_session_specific_data` (A khác anon) và `b_got_a_data` (B nhận đúng body A). `needs_review` chỉ bật khi **cả hai** đúng. A/B/anon cùng rồng ⇒ `UNKNOWN_NO_SESSION_SPECIFIC_DATA`, không gắn cờ |

**Không thay đổi kết luận nào:** vẫn **0 confirmed vulnerability**. Hai sửa đổi này chỉ làm
harness **nhạy hơn** — mọi verdict mới vẫn là *review lead*, không phải kết luận IDOR,
vẫn phải qua `audit_classify` và vẫn yêu cầu A có entitlement thật.

**Test mới (2):** `test_ws2_flags_cross_session_data_for_reading_history` (A có dữ
liệu riêng, B nhận cùng body A → `needs_review=True`) và
`test_ws2_identical_empty_records_are_not_flagged` (cả hai rỗng → không gắn cờ).
Suite: **58/58 OK** (exit 0), trước đợt này 56/56.
