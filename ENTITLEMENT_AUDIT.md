# ENTITLEMENT AUDIT — 3 lớp: server authz / content delivery / cache

Ngày 2026-11-14, 20:4x GMT+7. Script: `ttm_entitlement_audit.py`
→ `recon/entitlement_audit.json` (mẫu) và `recon/entitlement_sweep.json` (**toàn bộ 51 chương**).
CHỈ GET, 1 luồng, nghỉ 2s, không POST mutate, không brute force, không đọc file cấu
hình/bí mật. **Không có cookie thật** → mọi kết luận là anonymous.

> ⚠️ Sửa lỗi đo lường quan trọng: response `text/x-component` không kèm charset nên
> `requests` decode ISO-8859-1, làm tiếng Việt mojibake và **độ dài body giả tăng**
> 38 103 → 49 245 ký tự. Đã ép UTF-8 (`get()`), và `resolve_content()` giờ đi theo
> tham chiếu `content` (`$1b` ở HTML, `$15` ở RSC) thay vì hard-code chunk `1b`.
> Sau sửa: HTML và RSC cùng **38 103** ký tự, excerpt giống hệt.

---

## Câu 1 — Server authorization: nội dung có được kiểm tra entitlement TRƯỚC khi trả về không?

**Kết luận (anonymous): CÓ, ở mức đầu ra.** Server tự quyết định `locked` và cắt
`content` trước khi serialize; không có dữ liệu nào để client tự "bật" lại.

| Thử | Số lượng | Kết quả |
|---|---|---|
| Query param tự gán quyền (`?preview=1`, `?unlocked=1`, `?vip=1`, `?isPreview=1`, `?force=1`, `?admin=1`, `?key=1`, `?chapterId=1`, `?content=full`, `?bypass=1`) | 10 | **10/10** `locked:true`, `content:""`, `body=0` |
| Header giả quyền (`X-User-Role`, `X-VIP`, `X-Forwarded-User`, `X-Original-URL`, `X-Rewrite-URL`, `X-Middleware-Subrequest`) | 6 | **6/6** `locked:true`, `content:""`, `body=0` |
| Cookie variants (không / `probe_a` / `probe_b`) | 3 | **3/3** `locked:true`, `content:""`, `body=0` |

→ **0 leak candidate / 19 thử.** Độ lớn response chỉ dao động 39 312–39 389 bytes
(do `?q=` được phản chiếu), không phải do nội dung chương.

**Bằng chứng "trước khi trả về":** ngay cả kênh `text/x-component` (RSC thô, không có
DOM để ẩn/hiện) cũng trả `"locked":true, "content":""` và **không có chunk text `T…`**.
Chương mở thì có chunk `15` = 38 103 ký tự. Vậy quyết định nằm ở server component,
không phải CSS/JS phía client.

**Chưa chứng minh:** entitlement có được kiểm tra *trước khi truy vấn DB* hay không
(không có mã nguồn/timing side-channel). Và chưa chứng minh với tài khoản **đã mở
khoá** — cần `TTM_COOKIE_A`.

---

## Câu 2 — Content delivery: HTML, RSC, API có cùng áp dụng trạng thái khoá không?

**CÓ — 3 kênh + TOC + API nhất quán trên 51/51 chương.**

| Chương | Kênh | Content-Type | `locked` | `content` | body | DOM `prose` |
|---|---|---|---|---|---|---|
| 1 (mở) | HTML | `text/html` | false | `$1b` | **38 103** | 32 943 |
| 1 (mở) | RSC (`RSC:1`) | `text/x-component` | false | `$15` | **38 103** | n/a |
| 1 (mở) | prefetch | `text/html` | false | `$1b` | **38 103** | 32 943 |
| 4 (khoá) | HTML | `text/html` | **true** | **`""`** | **0** | **0** |
| 4 (khoá) | RSC (`RSC:1`) | `text/x-component` | **true** | **`""`** | **0** | n/a |
| 4 (khoá) | prefetch | `text/html` | **true** | **`""`** | **0** | **0** |

- HTML vs RSC body chương mở: **cùng 38 103 ký tự**, head/tail giống hệt, 261 CRLF.
- Chương khoá: cả 2 kênh **không có chunk `T…`**, `audioUrl` không có, DOM tổng 774
  ký tự với *"Chương này đang bị khóa. Đăng nhập để đọc tiếp."*
- **Sweep 51 chương**: `isLocked[]` (TOC) khớp `props.locked` (trang) **51/51**;
  **48 chương khoá đều `body=0`**, **3 chương mở đều có body** (38 103 / 46 326 / 72 698).
  `inconsistent = []`.
- **API**: 7 endpoint (`/api/stories`, `?include=chapters`, `/api/config`,
  `/api/favorites`, `/api/notifications`, `/api/user/audio-remaining`,
  `/api/chapters/<locked-id>/comments`) → **0** field `content`/`text`/`body`,
  **0** `audioUrl`, **0** `chapterNumber`, **0** `isLocked`. API không phải kênh
  phân phối nội dung chương, nên không có trạng thái khoá để "lệch".

**Kết luận:** không có kênh nào trả nội dung chương khoá; không có lệch trạng thái
giữa render lần đầu (HTML), điều hướng client (RSC), prefetch, TOC và API.

---

## Câu 3 — Cache: nội dung đã mở khoá có bị lưu / phân phối nhầm sang phiên chưa mở khoá không?

**Hiện KHÔNG quan sát được hiện tượng đó — nhưng CHƯA CHỨNG MINH ĐƯỢC triệt để**
(vì thiếu phiên A đã mở khoá). Bằng chứng ủng hộ:

| Kiểm tra | Kết quả |
|---|---|
| `/api/config` (có `s-maxage=300`) gọi 3 lần liên tiếp | `cf-cache-status: DYNAMIC` cả 3; body hash `76eac9234a` không đổi; **không** `Age`, **không** ETag → không có CDN cache hit |
| Response chứa nội dung (`/doc/1.html`, `/doc/1.css`, `/doc/1.png`, RSC, prefetch) | `DYNAMIC` hoặc **`BYPASS`**; `Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate`; không `Age`/ETag/`Set-Cookie` |
| Cache-key: anon / `probe_a` / `probe_b` / `Authorization` / query | cùng `DYNAMIC`, body hash của 2 cookie giả **`0166f3cb92`** (giống nhau); không có response nào mang dữ liệu của "phiên kia" |
| Luân phiên RSC ↔ HTML 5 lần | `text/x-component` ↔ `text/html` luôn đúng theo request, hash lặp đúng cặp (`87100b8e` / `3274c3dd`) → `Vary: RSC,…` tách đúng, không lẫn payload |
| 404 / gate / auth routes | đều `private, no-store`, `DYNAMIC` |

**Điểm yếu cấu hình vẫn còn (chưa phải lỗ hổng đã chứng minh):**
- `Vary` = `RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding` — **thiếu `Cookie`** trên mọi route.
- `/api/config` có `public, s-maxage=300, stale-while-revalidate=60` **lẫn** `private, no-store…` trong cùng header; 5 route bị set `Cache-Control` trùng 2 lần.
- `.css` / `.png` trả **HTML chương đầy đủ** (127 303 bytes) với `cf=BYPASS`. Đây là
  dạng **cache deception surface**: nếu sau này CDN rule đổi sang cache theo extension
  mà vẫn không `Vary: Cookie`, response của phiên đã mở khoá có thể bị lưu nhầm.

→ Hiện `DYNAMIC/BYPASS` + `no-store` đang **ngăn** được việc lưu. Khẳng định "không
phân phối nhầm" chỉ chắc chắn với anonymous; để chốt cần test 2 phiên thật.

### Cái còn thiếu để chốt câu 3

Script đã có sẵn chế độ `--sessions` (A→B→A→anon trên **cùng URL**, log hash +
`locked` + `body_chars` + excerpt, chỉ log 8 ký tự đầu SHA-256 của cookie):

```bash
export TTM_COOKIE_A='<phiên đã mở khoá chương 4>'
export TTM_COOKIE_B='<phiên chưa mở khoá>'
python ttm_entitlement_audit.py --sessions
```

Tiêu chí đọc kết quả:
- A `locked:false`, `body>0` **mới** đủ điều kiện kết luận (nếu A vẫn `locked:true`
  thì cả 2 chưa có entitlement, test vô nghĩa).
- `B_received_A_content = true` → **cache/entitlement leak đã chứng minh**.
- `false` + B `locked:true, body=0` → cách ly đúng.
- Kiểm tra thêm `A_again` và `anon` để phát hiện staleness.

---

## Tổng kết 3 lớp

| Lớp | Câu hỏi | Kết luận | Độ tin cậy |
|---|---|---|---|
| Server authorization | entitlement trước khi trả về? | **Có**, 19/19 thử tự gán quyền thất bại; RSC thô cũng cắt `content` | Cao (anonymous) |
| Content delivery | HTML/RSC/API cùng trạng thái khoá? | **Có**, 6 kênh + **51/51 chương** nhất quán, 0 API field body | Cao (anonymous) |
| Cache | nội dung mở khoá lưu/nhầm sang phiên khác? | **Chưa quan sát** (`DYNAMIC/BYPASS`, `no-store`, Vary tách đúng RSC/HTML). **Chưa chứng minh** thiếu 2 phiên thật | Trung bình — chờ `--sessions` |

**Không vội phân loại:** `Vary` thiếu `Cookie`, `Cache-Control` mâu thuẫn/lặp, và
`.css/.png` trả HTML là **hardening / bề mặt cần theo dõi**, chưa phải finding khai thác
được khi chưa có response chứng minh dữ liệu lọt sang phiên khác.

## Definition of done

- [x] 19 thử client-controlled entitlement → 0 leak
- [x] 3 kênh delivery đối chiếu, HTML = RSC 38 103 ký tự
- [x] Sweep 51/51 chương, 0 inconsistent
- [x] 7 API endpoint, 0 field body
- [x] Cache: 3× repeat, 7 cache-key variants, 5× RSC/HTML alternate
- [ ] `--sessions` với `TTM_COOKIE_A` (đã mở khoá) / `TTM_COOKIE_B`
- [ ] Retest sau khi có rule CDN mới (deployment đổi 3 lần trong phiên trước)
