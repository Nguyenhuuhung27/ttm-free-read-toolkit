# CONTROL AUDIT — phân lớp kiểm soát, F2 & cấu hình

Ngày: 2026-11-14, 20:0x GMT+7. Script: `ttm_control_audit.py` → `recon/control_audit.json`
+ `recon/audit/*` (response thô). **Chỉ GET/OPTIONS**, 1 luồng, nghỉ 2s, không POST
mutate, không thử `/.env`, `/.git/*`, `/package.json` hay bất kỳ file cấu hình/bí mật nào.
`TTM_COOKIE` vẫn rỗng → mọi kết luận dưới đây là **anonymous**, không đại diện cho tài
khoản đã đăng nhập/VIP.

---

## 1. Câu hỏi 1 — Route có đi qua access gate không?

**Có, nhưng gate là lớp middleware theo path, không phải lớp dữ liệu.**

| Route | Kết quả | Gate? |
|---|---|---|
| `/`, `/truyen`, `/truyen/<slug>`, `/doc/1`, `/doc/4`, `/nghe/1` | 307 → `/khong-co-pass?next=…` | **CÓ** |
| `/dang-nhap`, `/khong-co-pass`, `/robots.txt`, `/sitemap.xml` | 200 | KHÔNG (whitelist hợp lý) |
| `/_next/static/chunks/…` | 200 | KHÔNG (static hợp lý) |
| **`/api/config`, `/api/stories`, `/api/favorites`, `/api/auth/session`** | **200** | **KHÔNG** |
| `/doc/1.html` (và mọi đuôi có dấu chấm) | **200** | **KHÔNG** |

Header của chính response 307: `Server: cloudflare`, `Location: …/khong-co-pass?next=…`,
không có `x-middleware-*` / `x-nextjs-*` → gate do **middleware/edge redirect**, trước khi
server component chạy. `/api/config` công khai `access_gate_enabled:"1"`.

### Xác định chính xác lớp bị bỏ qua

Probe 10 biến thể (cùng `doc/1`, chỉ đổi đuôi):

| Đuôi | status | gate |
|---|---|---|
| (không) | **307** | CÓ |
| `.html` `.json` `.txt` `.css` `.png` `.` `.xhtml` `%2Ehtml` | **200** | **KHÔNG** |
| `.html/x` | 404 | KHÔNG |

→ **Không phải riêng `.html`.** Matcher của middleware bỏ qua mọi path có **dấu chấm ở
segment cuối** (kiểu `matcher` loại trừ file tĩnh `/\..*\..*/`). Hệ quả: Next.js vẫn resolve
`doc/1.html` thành `chapter = "1.html"` rồi **parse về số 1** (đã thấy
`["chapter","1.html","d"]` trong flight stream). Đây là **lỗi cấu hình matcher**, không phải
"endpoint bí mật", cũng không phải bypass xác thực.

**Lớp bị bỏ qua: L1 — access gate (middleware redirect).**
**Lớp KHÔNG bị bỏ qua: L2 — entitlement chương trong server component** (mục 2).

---

## 2. Câu hỏi 2 — Trang có hiển thị nội dung chương không?

So sánh **cùng một route, cùng status 200**, khác `locked`:

| | ch.1 (`locked:false`) | ch.4 (`locked:true`) |
|---|---|---|
| HTTP | 200 | **200** |
| bytes HTML | 127 307 | 39 312 |
| `props.content` | `"$1b"` (tham chiếu chunk text) | **`""`** |
| RSC body (chunk `1b:`) | **38 103 ký tự** | **0** |
| DOM `div.prose` | **32 943 ký tự** | **0** |
| DOM tổng | 33 647 | **774** |
| Chuỗi dài nhất trong payload | 278 (script theme) | 278 (script theme) |
| `audioUrl` / URL media | không | không |
| TOC `chapters[]` | 51 | 51 (chỉ metadata) |

DOM của chương khoá, nguyên văn:
> `Chương 4 : Chương 16-20  Chương này đang bị khóa. Đăng nhập để đọc tiếp. …`

**Kết luận bắt buộc: HTTP 200 KHÔNG đồng nghĩa với đọc được nội dung VIP.** Với chương
khoá, 200 chỉ nghĩa là "trang placeholder được render". Server trả `content:""`, không
đẩy chunk `1b:` text, không render `div.prose`, không có URL audio. Chưa có bằng chứng nào
cho thấy nội dung chương khoá bị rò rỉ qua payload, DOM hay TOC.

---

## 3. Câu hỏi 3 — API phía server có thực sự cấp dữ liệu bị khóa không?

11 endpoint đã xác minh tồn tại, gọi anonymous với `chapterId` của **chương 4 (khoá)**:

| Kiểm tra | Kết quả |
|---|---|
| Field `"content"` / `"text"` / `"body"` / `"chapterText"` | **không có** ở 11/11 |
| `audioUrl` / `.mp3` / `.m4a` / `.m3u8` | **không có** ở 11/11 |
| `/api/chapters/<locked-id>/comments` | `{"comments":[]}` |
| `/api/user/audio-remaining` | `{"remaining":null}` |
| `/api/favorites`, `/api/notifications`, `/api/listening-history` | rỗng |
| `/api/stories?limit=5` chuỗi dài nhất | **1 644 ký tự**, field `contentDescription` = **mô tả truyện công khai**, không phải body chương |

→ **Không.** Không có API nào trả dữ liệu chương bị khoá cho anonymous. Dữ liệu chương mở
đi qua **server component render** (DOM + RSC chunk), không qua REST API.

### Ảnh hưởng thực tế (đã chứng minh)

| Có được | Không có được |
|---|---|
| Truy cập trang công khai dù gate đang bật | Nội dung chương `locked:true` |
| 3 chương miễn phí (đã lưu ở `download/`) | Audio VIP / `audioUrl` |
| TOC 51 chương (title + `hasAudio` + `isLocked`) | Dữ liệu user khác, phiên, secret |
| Metadata `/api/stories`, `/api/config`, comments rỗng | Bất kỳ field body nào từ API |

→ Đây là **bypass kiểm soát truy cập ở tầng gate**, mức độ ảnh hưởng **giới hạn ở nội
dung công khai**. Không phải leo thang đặc quyền, không phải lộ dữ liệu trả phí.

---

## 4. F2 — Information Disclosure (retest trên deployment hiện tại)

Báo cáo cũ: *"thông tin phiên bản framework, PHP và đường dẫn nội bộ"*.

| Nội dung cũ | Retest | Bằng chứng |
|---|---|---|
| **PHP / `PHP/x.y` / `.php`** | **KHÔNG tái hiện** | 0 match trong 8 response lỗi; không có PHP trong HTML chương |
| **Phiên bản framework** | **KHÔNG tái hiện** | 0 match `PHP/\d`, `Next.js \d`, `next@\d`, `react@\d`, `v\d.\d.\d`, `Apache/`, `nginx/`, `node/` |
| **Đường dẫn nội bộ (FS)** | **KHÔNG tái hiện** | 0 match `/var/www`, `/home/…`, `C:\`, `.next/server`, `node_modules/`, `process.env.*`, `app/(public)` trong body lỗi |
| **Stack trace / exception chi tiết** | **KHÔNG tái hiện** | 0 match `at Object…`, `.js:line:col`, `PrismaClient`, SQL, `DATABASE_URL`, `NEXTAUTH_SECRET`, key patterns |

**Thông tin THỰC SỰ còn lộ** (đều là fingerprint/cấu hình, không phải dữ liệu nhạy cảm):

| Thông tin | Nơi xuất hiện | Phân loại |
|---|---|---|
| `Server: cloudflare` | mọi response | proxy/CDN, công khai |
| `X-Powered-By: Next.js` | 404 page, 404 API, gate page (**không có số phiên bản**) | tên framework |
| `Error: This action with HTTP GET is not supported by NextAuth.js` | `GET /api/auth/me` → 400, 64 bytes | tên thư viện, **không** có stack/path |
| `static/chunks/app/layout-….js`, `global-error-….js` | HTML 404 | **tên chunk build công khai** (client cần tải), không phải đường dẫn filesystem server |
| `?next=` tự phản chiếu | `/khong-co-pass?next=/etc/passwd` → `value="/etc/passwd"` | **self-reflection**: chính chuỗi do client gửi lên. `https://evil.example`, `javascript:`, `<script>` đều bị chuẩn hoá về `"/"`; raw `<script>` không xuất hiện |

### Xử lý lỗi / exception — đã ẩn chưa?

| Case | Status | Body | Đánh giá |
|---|---|---|---|
| `GET /api/auth/me` | 400 | `Error: This action with HTTP GET is not supported by NextAuth.js` | generic, **đã ẩn** stack/path |
| `GET /api/chapters/<id>/unlock` | 405 | rỗng (0 byte) | **đã ẩn** |
| `/api/stories?limit=not-a-number` | **500** | `{"error":"Internal error"}` (26 bytes) | **đã ẩn** stack; nhưng lỗi 500 do thiếu validate input — là lỗi xử lý input, **không** phải info disclosure |
| `/api/stories?limit=-1` | 200 | 3 001 bytes | clamp/âm không gây lỗi |
| `/api/stories?limit=99999999999999999999` | 200 | 132 837 bytes | **không clamp** → cần xem xét giới hạn tài nguyên (ngoài phạm vi F2) |
| 404 page / 404 API | 404 | HTML chuẩn, `<html id="__next_error__">` | không lộ buildId, không lộ path FS |
| `?error=1` gate | 200 | form + thông báo chung | không lộ lý do từ chối chi tiết |

**Kết luận F2:** các thông tin nhạy cảm nêu trong báo cáo cũ (phiên bản, PHP, đường dẫn
nội bộ, stack) **đã được ẩn / không còn tái hiện** trên deployment được phép kiểm tra.
Thứ còn lại là **thông tin cấu hình công khai** (tên framework, CDN, tên chunk). Đây là
hardening fingerprint, **không phân loại là lỗ hổng khai thác được**. Đã tuân thủ: không
request tới file cấu hình/bí mật.

---

## 5. Kiểm tra cấu hình bảo mật

> Mục này là **rà soát cấu hình**. Việc thiếu một header được ghi nhận là "điểm cần
> hardening", **không** tự động kết luận là lỗ hổng khai thác được — cần thêm điều kiện
> khai thác (ví dụ CSP chỉ quan trọng khi đã có XSS đã chứng minh).

| Hạng mục | Quan sát thật | Ghi nhận (mức cấu hình) |
|---|---|---|
| **Security headers** | 6/6 vắng trên **cả 4 loại** response (page, API, 404, gate): HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Cần hardening đồng loạt. Riêng HSTS: chưa kiểm tra HTTP→HTTPS redirect, nên chưa khẳng định thiếu hoàn toàn |
| **CORS** | 5 Origin (`evil.example`, `null`, cùng site, subdomain, `site.evil.example`) → **không** có `ACAO`/`ACAC`; preflight `OPTIONS` → **204, không có ACAO/ACAM** | **Không reflect Origin, không cho cross-origin đọc**. Baseline tốt; không có thiếu sót ở hạng mục này |
| **Cookie flags** | `__Host-next-auth.csrf-token`: `Path=/; HttpOnly; Secure; SameSite=Lax`, không `Domain` → đúng luật `__Host-`. `__Secure-next-auth.callback-url`: `HttpOnly; Secure; SameSite=Lax` → đúng luật `__Secure-` | Đạt. **Chưa kiểm tra được** session cookie thật (chưa đăng nhập) → vòng đời phiên vẫn là ẩn số |
| **Cache policy** | user-scoped routes: `private, no-store, max-age=0, must-revalidate`, `cf-cache-status: DYNAMIC`, không ETag → **không cache thực tế**. `/api/config`: `public, s-maxage=300, stale-while-revalidate=60, private, no-store, …` → **mâu thuẫn**. `/api/auth/session`, `/api/auth/csrf`, `/api/listening-history`, `/doc/1.html`, 404: header **`Cache-Control` lặp 2 lần**. `Vary` = `Accept-Encoding, RSC, Next-Router-State-Tree, Next-Router-Prefetch` → **thiếu `Cookie`** | Hiện **không có leak giữa phiên** (đã đo anon vs cookie giả: cùng hash `3e86695c`, `DYNAMIC`). Cần hardening: bỏ `public/s-maxage` trên config, gộp header trùng, thêm `Vary: Cookie` cho route user-scoped. **Chưa chứng minh được** khai thác — cần 2 tài khoản thật |
| **Xử lý lỗi / exception** | 500 → `{"error":"Internal error"}`; 405 → rỗng; 400 → generic NextAuth; 404 → HTML chuẩn. **Không** stack/SQL/env/secret | Đã ẩn thông tin nhạy cảm ✅. Vấn đề còn lại là **validate input** (`limit` gây 500, `limit` cực lớn không clamp) — xếp vào robustness, không phải info disclosure |

---

## 6. Điều chưa làm / giới hạn bằng chứng

- Không có `TTM_COOKIE` → **chưa** test entitlement sau đăng nhập, session cookie flags,
  revoke phiên, hay cache isolation giữa 2 phiên thật. Mọi kết luận "không lộ" ở mục 3
  đúng với **anonymous**, cần retest với tài khoản A/B trước khi khẳng định tổng quát.
- Không POST mutate (unlock, comment, access-gate), không brute force `key`.
- Không request tới file cấu hình/bí mật (theo yêu cầu F2).
- F2 chỉ retest qua response lỗi tự nhiên; không có mô tả gốc của F2 trong repo, nên kết
  luận dựa trên 3 nội dung bạn nêu (phiên bản / PHP / đường dẫn nội bộ).

## 7. Kết luận ngắn gọn

1. **Lớp bị bỏ qua = L1 access gate (middleware matcher bỏ qua path có dấu chấm)**, không
   phải lớp entitlement. Ảnh hưởng thật: đọc được **nội dung công khai** dù gate bật.
2. **HTTP 200 trên chương khoá = trang placeholder** (`content:""`, DOM 774 ký tự,
   "Chương này đang bị khóa"). Không đọc được nội dung VIP.
3. **Không có API nào cấp dữ liệu bị khoá** cho anonymous (11 endpoint, 0 field body).
4. **F2 đã được ẩn**: không còn phiên bản/PHP/đường dẫn nội bộ/stack; chỉ còn fingerprint
   cấu hình công khai.
5. **Cấu hình**: CORS và cookie flags đạt; 6 security headers vắng, `Cache-Control` mâu
   thuẫn/lặp, `Vary` thiếu `Cookie`, `limit` thiếu validate → **hardening**, chưa vội xếp
   thành lỗ hổng khai thác được.
