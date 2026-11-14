# TESTPLAN — tieuthuyetmang.com (v2, deployment 2026-11-14)

Tài liệu này là **ma trận kiểm thử có ủy quyền**. Mọi testcase dưới đây giả định:
bạn có scope/pentest authorization bằng văn bản cho domain này, và dùng **2 tài
khoản do chính bạn tạo** (A = free, B = VIP). Không động đến dữ liệu của user khác,
không brute force `key`, không POST làm thay đổi dữ liệu production.

Baseline đo lúc 19:14 → 19:2x GMT+7, xem mục 0. Chạy `python ttm_passive_check.py` để đo lại.

> ⚠️ **Deployment thay đổi ngay trong lúc khảo sát**: `sitemap lastmod` lần lượt
> `2026-11-14T05:11:37Z` → `2026-11-13T17:19:30Z` → `2026-11-14T06:31:36Z`,
> và `/doc/1.html` tăng 104 921 → 127 350 bytes. Parser đã chạy lại trên bản mới:
> ch.1 body 38 103 ký tự / `locked:false`, ch.4 body 0 / `locked:true`, TOC 51 chương
> → **cấu trúc RSC không đổi**, finding vẫn có giá trị. Mọi retest phải ghi kèm
> `lastmod` + `body_sha256_8` để biết đang nói về bản nào.

---

## 0. Baseline đã đo (không suy đoán)

| Quan sát | Giá trị thật | Ý nghĩa |
|---|---|---|
| `GET /api/config` Cache-Control | `public, s-maxage=300, stale-while-revalidate=60, private, no-store, max-age=0, must-revalidate` | **Mâu thuẫn**: vừa `public/s-maxage` vừa `private/no-store` trong cùng header |
| User-scoped endpoints (`/api/favorites`, `/api/notifications`, `/api/user/audio-remaining`, `/api/listening-history`) | `private, no-store, max-age=0, must-revalidate`; `cf-cache-status: DYNAMIC` | Hiện **không** cache → chưa có leak, nhưng `Vary` thiếu `Cookie` |
| `Vary` (mọi API) | `Accept-Encoding, RSC, Next-Router-State-Tree, Next-Router-Prefetch` | **Không có `Cookie`** → nếu ai đó bật `s-maxage` trên route user-scoped là leak cache ngay |
| Security headers trên `/dang-nhap` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy: **đều vắng** | Bề mặt XSS/clickjacking/MIME rộng |
| CSRF cookie | `__Host-next-auth.csrf-token=…; Path=/; HttpOnly; Secure; SameSite=Lax` | Đúng chuẩn NextAuth (`__Host-` + no Domain + Path=/) |
| CORS | Gửi `Origin: https://evil.example` → **không** có `ACAO`/`ACAC` trên `/api/config`, `/api/favorites`, `/api/chapters/<id>/comments` | Không reflect Origin; baseline tốt |
| Sitemap `lastmod` | `2026-11-14T06:31:36.718Z` (các lần đo trước: `05:11:37.633Z`, `2026-11-13T17:19:30.465Z`) | **Deployment thay đổi 3 lần** → retest F2 phải gắn fingerprint |
| Bypass `.html` | `/doc/1` → 307 gate; `/doc/1.html` → 200, **127 350 bytes** (trước đó 104 921) | **Vẫn còn** trên deployment mới (chưa fix) |
| `Cache-Control` trên `/api/auth/session`, `/api/listening-history` | giá trị **lặp lại 2 lần** (`private, no-cache, no-store, private, no-store, …`) | Header bị set trùng (route handler + middleware) → cần kiểm tra header nào có hiệu lực |
| `Vary` (mọi API) | `Accept-Encoding, RSC, Next-Router-State-Tree, Next-Router-Prefetch` | **Không có `Cookie`** → nếu ai đó bật `s-maxage` trên route user-scoped là leak cache ngay |
| Kiểm tra cache thực tế | `/api/favorites` anon vs cookie giả: cùng hash `3e86695c`, `cf-cache-status: DYNAMIC` | Hiện **không** leak; `Vary` thiếu `Cookie` vẫn là điểm yếu cấu hình |
| `access_gate_enabled` | `1` trong `/api/config` | Gate vẫn bật |
| `TTM_COOKIE` | rỗng | Mọi test auth/IDOR/VIP **chưa chạy được** — cần cookie của 2 tài khoản test |

---

## 1. Authorization / IDOR — quyền sở hữu từng đối tượng

**Mục tiêu:** chứng minh server kiểm tra `owner` ở *mọi* object, không chỉ ở UI.

| TC | Cách thử (account A sở hữu, account B tấn công) | Pass | Bằng chứng cần lưu |
|---|---|---|---|
| IDOR-01 | Lấy `chapterId`, `storyId`, `comment.id` của A; gọi lại với cookie B | 403/404 hoặc empty | request/response thô, 2 cookie khác nhau (hash, không lưu giá trị) |
| IDOR-02 | `GET /api/chapters/<chapterId>/comments` — thay `<chapterId>` bằng ID chương của truyện khác | Không trả comment lạ | so sánh `comments[]` length |
| IDOR-03 | `GET /api/favorites`, `/api/notifications`, `/api/listening-history?chapterId=<id>` với cookie B | Chỉ trả dữ liệu của B | JSON 2 bên, diff |
| IDOR-04 | `GET /api/user/audio-remaining?userId=<id A>` (thử cả body/query) | Bỏ qua param, trả của B | JSON |
| IDOR-05 | ULID của `story.id`/`chapter.id` là `01K…` (time-sortable) → thử ID lân cận **cùng account**, không enumerate hàng loạt | Không lộ object ngoài scope | log 5–10 ID, nghỉ 2s |
| IDOR-06 | So sánh `isLocked` trên `/doc/<N>.html` giữa A và B cùng chương | Phải khác nếu A đã mở khoá | bảng `chapterNumber → isLocked` |

**Điểm cần đối chiếu:** `content` của chương khoá đã đo là `""` ở server (FINDINGS §4) —
đây là mẫu *đúng*. Nếu tìm được route nào trả `content` khác rỗng cho `locked:true`,
đó là finding mới. Dò theo hướng **so sánh entitlement**, không dò mù field.

---

## 2. Business logic / VIP — đối chiếu entitlement giữa các chức năng

**Mục tiêu:** một entitlement phải được quyết định **một lần, phía server**, và dùng chung
cho mọi chức năng. Sai lệch giữa các chức năng = logic bug.

| TC | Đối chiếu | Kỳ vọng |
|---|---|---|
| VIP-01 | `/api/user/audio-remaining` (A: `null`) ↔ `/nghe/<N>.html` render `audioUrl` hay "Audio bị khóa" ↔ `/api/listening-history` có nhận POST progress không | Cùng 1 quyết định |
| VIP-02 | Đọc `/doc/<N>.html` (A bị `locked:true`) ↔ đăng nhập A rồi gọi lại ↔ `/api/chapters/<id>/comments` có cho A comment không | Chương khoá không cho tương tác đọc |
| VIP-03 | `remainingDailyUnlocks`, `nextChapterLocked` trong props ↔ `isLocked[]` trong `chapters[]` ↔ gate mở khoá hàng ngày | 3 nguồn phải khớp |
| VIP-04 | `POST /api/chapters/<id>/unlock` (405 với GET) — thử **trên tài khoản A của bạn**, 1 lần, kiểm tra số dư trước/sau | Không âm, không unlock chương đã mở, không tặng thêm lượt |
| VIP-05 | Gói "Linh Tu" vs "Tiên Nhân": thử downgrade (nếu có gói dùng thử) rồi gọi lại `/nghe` | Thu hồi quyền ngay, không chờ hết phiên |
| VIP-06 | Gửi `chapterId` của chương **không có audio** (`hasAudio:false`) tới các route audio | Không trả URL suy ra được |

⚠️ VIP-04 là test **có tác động** (đổi số dư/lượt unlock). Chỉ làm trên tài khoản test,
ghi rõ trước/sau, và xin phép nếu scope không cho mutate. Không test trên tài khoản thật.

---

## 3. API security — xác thực & phân quyền

**Endpoint đã xác minh tồn tại** (đừng bịa thêm):
`/api/stories` (`?limit=` có tác dụng), `/api/config`, `/api/categories`, `/api/search`,
`/api/favorites`, `/api/notifications`, `/api/recommend`, `/api/listening-history`,
`/api/user/audio-remaining`, `/api/chapters/<id>/comments`, `/api/chapters/<id>/unlock`,
`/api/auth/{session,providers,csrf,signin,callback}`, `/api/access-gate`.

| TC | Cách thử | Pass |
|---|---|---|
| API-01 | Gọi mỗi route với: không cookie / cookie hết hạn / cookie sửa 1 ký tự | 401/403 nhất quán, không 200 với dữ liệu |
| API-02 | Thử method sai (OPTIONS/PUT/PATCH/DELETE) trên route chỉ GET | 405 + không mutate |
| API-03 | Thử `/api/*` mà **không** qua access gate (đã thấy `/api/stories` trả 200 dù `/truyen` 307) | Gate phải bảo vệ cả API, không chỉ page |
| API-04 | Bỏ `Referer`/dùng `Referer` lạ trên `/api/access-gate` | Không lộ lý do từ chối chi tiết |
| API-05 | So sánh response anonymous vs auth của `/api/config` | Không chèn dữ liệu user vào response được cache public |
| API-06 | Rate limit: 10 req tuần tự cách 2s tới 1 route, quan sát 429 | Có backoff, không lock account thật |
| API-07 | `?limit=100000`, `?page=-1`, `?chapterId=` kiểu sai | Bị clamp, không 500 stack trace |

**Chú ý API-03:** đã đo `/api/stories`, `/api/config`… đều 200 khi anonymous, trong khi
mọi `/truyen/*` bị gate. Đây là **khác biệt phân quyền giữa page và API** — đáng viết
thành finding riêng nếu gate được kỳ vọng là chặn toàn bộ site.

---

## 4. Session security — vòng đời phiên

| TC | Cách thử | Pass |
|---|---|---|
| SES-01 | Đăng nhập A → lưu cookie → đổi mật khẩu/logout → gọi lại `/api/auth/session`, `/api/favorites` | Session cũ vô hiệu ngay |
| SES-02 | Đăng nhập A trên 2 trình duyệt, logout 1 bên | Bên kia cũng mất (hoặc có cơ chế revoke rõ ràng) |
| SES-03 | Kiểm tra đủ flag: `__Host-`/`__Secure-`, `HttpOnly`, `Secure`, `SameSite`, `Path=/`, `Domain` vắng | Baseline đã đạt (mục 0) |
| SES-04 | Cookie `next-auth.session-token` thay đổi sau login? Có rotate không? | Rotate sau privilege change |
| SES-05 | Set cookie `__Secure-next-auth.callback-url` trỏ domain lạ → đăng nhập | Không open redirect |
| SES-06 | `/api/auth/csrf`: token có bind vào session không? Dùng token của A với cookie B | Bị từ chối |
| SES-07 | Để phiên idle 30p / 24h rồi gọi `/api/auth/session` | Expiry đúng chính sách, không vô hạn |
| SES-08 | `SameSite=Lax` + `POST /api/access-gate` cross-site | CSRF token/Origin check chặn được |

---

## 5. Cache isolation — cách ly giữa các phiên

**Đây là nhóm có tín hiệu mạnh nhất ở baseline** (Cache-Control mâu thuẫn + `Vary` thiếu `Cookie`).

| TC | Cách thử | Pass |
|---|---|---|
| CCH-01 | A đăng nhập (có favorites) → GET `/api/favorites`; ngay sau đó B/anon GET cùng URL | Response của B **không** chứa favorites của A |
| CCH-02 | Lặp CCH-01 nhưng thêm header `RSC:1` / `Next-Router-State-Tree` khác nhau | `Vary` chỉ liệt kê các header này → phải có `Cookie` hoặc `private, no-store` tuyệt đối |
| CCH-03 | `GET /api/config` 2 lần cách 5 phút, so sánh `Age`, `cf-cache-status`, body | Nếu `public, s-maxage=300` có hiệu lực → ai thêm field user-specific vào config là leak |
| CCH-04 | Gửi `Authorization` / `Cookie` giả lên `/doc/<N>.html` rồi so sánh body với anon | Không cache nhầm bản đã đăng nhập cho khách |
| CCH-05 | Thử `?__rsc=`, `?_rsc=` và header `RSC` trên `/truyen/*` | Không trả RSC payload của user A cho user B |
| CCH-06 | So sánh `cf-cache-status` giữa `/api/config` (có `s-maxage`) và `/api/favorites` | `DYNAMIC` cho mọi route user-scoped |

Cách chứng minh sạch: 2 session `requests` riêng biệt, log **status + độ dài + hash body**
(không log cookie), chạy A→B→A để phát hiện staleness.

---

## 6. XSS / CSRF — chức năng tương tác người dùng

Bề mặt tương tác đã thấy: `/api/chapters/<id>/comments` (GET + POST `content`),
`/api/chapter-errors`, `/api/reading-history`, `/api/favorites`, `/api/access-gate`,
NextAuth `signin/callback`. **Không có CSP/X-Frame-Options/X-Content-Type-Options** (mục 0).

| TC | Cách thử (trên tài khoản test) | Pass |
|---|---|---|
| XSS-01 | POST comment `<img src=x onerror=alert(1)>` → xem lại GET comments và trang `/doc/<N>.html` | Escape/encode, không execute |
| XSS-02 | Payload trong `chapterTitle`, `authorNote`, `storyTitle`, nội dung báo lỗi | Render an toàn ở mọi nơi, kể cả RSC `1b:` chunk |
| XSS-03 | Kiểm tra `dangerouslySetInnerHTML` (đã thấy trong layout: theme script + `custom_head_html` từ `/api/config`) | Giá trị admin-config phải được sanitize |
| XSS-04 | `Content-Type` sai / upload `.svg` nếu có avatar upload | `X-Content-Type-Options: nosniff` |
| CSRF-01 | POST `/api/chapters/<id>/comments` **không** kèm `csrfToken` | 403 |
| CSRF-02 | Form cross-origin (Origin lạ) gửi POST comment + favorites | Bị chặn bởi `SameSite=Lax` + CSRF token + Origin check |
| CSRF-03 | Dùng `csrfToken` của A với cookie B (xem SES-06) | Bị từ chối |
| CSRF-04 | `POST /api/access-gate` từ origin khác với `next` trỏ external | Không open redirect, không set gate cookie |
| CSRF-05 | Clickjacking: thử frame `/dang-nhap` (không có X-Frame-Options/CSP frame-ancestors) | Nên có chống đóng khung |

⚠️ Chỉ POST nội dung test vào tài khoản của bạn; xoá/cleanup sau khi xong.

---

## 7. Information disclosure — Retest F2 trên deployment mới

| TC | Cách thử | Kết quả retest 20:0x (`CONTROL_AUDIT.md` §4) |
|---|---|---|
| INF-01 | Bypass `.html` còn sống không | **CÒN**: 200 / 127 350 bytes. Mở rộng: **mọi đuôi có dấu chấm** (`.json/.txt/.css/.png/./.xhtml/%2Ehtml`) đều 200 → lỗi matcher middleware |
| INF-02 | `GET /khong-co-pass?error=1` có lộ lý do / key hợp lệ trong DOM không | **Không** lộ lý do; `?next=` chỉ self-reflect, external/`javascript:`/`<script>` bị chuẩn hoá về `/` |
| INF-03 | 404 page có lộ stack/buildId/path nội bộ không | **KHÔNG**: 0 match `/var/www`, `C:\`, `.next/server`, `node_modules/`, `process.env.*`, `buildId`, stack trace. Chỉ có tên chunk build công khai |
| INF-04 | `/api/config` có lộ secret — `ad_*_html`, `custom_*_html` | `custom_head_html` (GTM) — public; **không** có secret pattern (0 match `DATABASE_URL`/`NEXTAUTH_SECRET`/private key) |
| INF-05 | `robots.txt` / sitemap lộ route admin, `/api/*`, path ẩn | `sitemaps/0.xml` 45 000 loc, `1.xml` 23 510 loc `/doc/<N>` — public theo thiết kế |
| INF-06 | JS chunk lộ endpoint nội bộ, `NEXT_PUBLIC_*`, key | Đã trích: `/api/listening-history`, `/api/user/audio-remaining`, `/api/chapter-errors`, `/api/reading-history`, `/api/chapters/<id>/...` — không thấy secret |
| INF-07 | Error message / exception / phiên bản / PHP | **Không còn phiên bản, PHP, stack**. 500 → `{"error":"Internal error"}` (26 bytes), 405 → rỗng, 400 → generic NextAuth, `X-Powered-By: Next.js` (không số phiên bản) |
| INF-08 | So sánh `lastmod` / chunk hash / độ dài `/doc/1.html` giữa 2 lần đo | **Đã đổi 3 lần trong cùng phiên** (mục 0) → retest có giá trị, bắt buộc gắn fingerprint |

**Kết luận retest F2 (20:0x):** các thông tin nhạy cảm trong báo cáo cũ — phiên bản
framework, PHP, đường dẫn nội bộ — **không còn tái hiện**; response lỗi đã ẩn stack/SQL/
env/secret. Thứ còn lại là fingerprint cấu hình công khai (`Server: cloudflare`,
`X-Powered-By: Next.js`, tên chunk). **Không phân loại thành lỗ hổng khai thác được.**
Không hề request tới file cấu hình/bí mật. Chi tiết: `CONTROL_AUDIT.md` §4.
F1 (bypass gate) **vẫn tồn tại** nhưng chỉ mở nội dung công khai (§1–3 của báo cáo đó).
Mô tả gốc F2 vẫn chưa có trong repo → kết luận dựa trên 3 nội dung user nêu.

---

## 8. Thứ tự ưu tiên (theo tín hiệu / chi phí)

1. **Cache isolation (CCH-01/02/06)** — baseline có mâu thuẫn `public/s-maxage` vs `private/no-store` và `Vary` thiếu `Cookie`. Rẻ, chỉ cần 2 account.
2. **API-03** — phân quyền lệch giữa `/api/*` (200 anonymous) và `/truyen/*` (307 gate). Đã có bằng chứng, chỉ cần viết report.
3. **Session (SES-01/06)** + **CSRF (CSRF-01/03)** — kế thừa trực tiếp cặp cookie đã đo.
4. **IDOR-01/03/06** — cần 2 account, nhưng endpoint đã biết chính xác.
5. **VIP-01/03** — đối chiếu 3 nguồn entitlement, không cần mutate.
6. **XSS-01/02** + thiếu security headers — cần quyền POST trên tài khoản test.
7. **INF retest F2** — chờ mô tả gốc.

## 9. Quy tắc chạy (giữ nguyên từ CLAUDE.md)

- 1 luồng, nghỉ **≥2s**/request; backoff khi 403/429; dừng ngay nếu có dấu hiệu chặn.
- Lưu response thô vào `recon/` trước khi parse; ghi URL, status, độ dài, hash body.
- **Không log giá trị cookie/token** — chỉ log SHA-256 8 ký tự đầu để phân biệt phiên.
- Không enumerate hàng loạt, không brute force `key` của `/api/access-gate`.
- Ghi cả giả thuyết bị bác bỏ vào `FINDINGS.md`.
- Mọi kết luận phải kèm output thật; không tuyên bố "có lỗ hổng" khi chưa có response chứng minh.

## 10. Definition of done

- [ ] Có 2 tài khoản test (A free, B VIP) + `TTM_COOKIE_A` / `TTM_COOKIE_B`
- [ ] `ttm_passive_check.py` chạy lại ra baseline khớp mục 0
- [ ] Mỗi nhóm 1–7 có ≥1 testcase với request/response thô trong `recon/`
- [ ] Bảng `pass/fail` + giả thuyết bị bác bỏ cập nhật vào `FINDINGS.md`
- [ ] F2: có mô tả gốc + kết luận retest trên deployment mới
- [ ] Report ghi rõ scope, thời điểm, build/deployment fingerprint
