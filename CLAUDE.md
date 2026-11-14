# TTM Free-Read Toolkit — AI Behavior Contract (bản cập nhật 2026-11-14)

## Purpose

Toolkit cá nhân đọc & nghe truyện trên tieuthuyetmang.com: lấy nội dung mà
**trình duyệt của chính user đã nhận về** (văn bản chương + audio do trang tự
đọc), lưu thành file cục bộ để đọc/nghe offline.

Toàn bộ là HTTP GET + parse payload server đã gửi cho client. Không brute force,
không giả mạo thanh toán, không bypass khoá nội dung.

**Đọc `FINDINGS.md` trước khi sửa code** — mọi giả thuyết đã bị bác bỏ nằm ở đó.

---

## 1. Activation

Khi user nói `ttm start` (hoặc nhắc tới việc tải truyện/audio từ
tieuthuyetmang.com), kích hoạt tài liệu này và trả lời:

> TTM Free-Read mode active. Chỉ GET + parse, chạy cục bộ, dùng cookie của chính
> user, không phân phối lại.

---

## 2. Cơ sở hợp pháp

1. `robots.txt`: `User-agent: * → Allow: /`, `Content-Signal: search=yes, ai-train=no, use=reference`.
2. Dùng **phiên đăng nhập của chính user** (`TTM_COOKIE`). Chương tài khoản đã mở khoá thì đọc lại là quyền đã có.
3. Chỉ dùng cá nhân, không đăng lại, không bán.
4. Tải tuần tự, nghỉ 2 giây/request.

Giới hạn phải nói rõ khi bàn giao: đây là bản sao cá nhân; chương chưa mở khoá
bằng tài khoản thì **không có quyền đòi** và script sẽ không lấy được.

---

## 3. Cơ chế thật của site (đã đo — dùng số liệu này, đừng đoán)

| Vấn đề | Kết luận |
|---|---|
| Access gate | `access_gate_enabled=1`; mọi `/truyen/*` → 307 `/khong-co-pass` (form `POST /api/access-gate`, field `key`) |
| **Bypass** | Thêm hậu tố `.html` vào path → 200, qua gate (vd `/truyen/<slug>/doc/26.html`) |
| Body chương | Trong RSC flight stream, chunk `1b:` (dạng `1b:T16050,<text>`; bỏ tiền tố `T<hex>,`) |
| Chunk splitting | Regex `(?m)^(1[0-9a-f]\|[0-9a-f]):` — payload có newline thật, không split dòng |
| Chương khoá | `locked:true` → `content:""`, chunk `1b:` là module ref → **không có body trong payload** |
| TOC | Mảng `chapters[]` nằm trong payload của `/doc/<N>.html` (landing `/truyen/<slug>` 404) |
| Audio | `/nghe/<N>.html` chỉ có `audioUrl` khi đủ hạng VIP; anonymous thấy "Audio bị khóa" |
| API thật | `/api/stories` (list, `?limit=`), `/api/config`, `/api/categories`, `/api/chapters/<id>/comments`, `/api/user/audio-remaining` |

Endpoint nào không có trong bảng trên → coi như **không tồn tại**, đừng bịa.

---

## 4. Chuẩn hoá thuật ngữ

| User nói | Nghĩa kỹ thuật ở đây |
|---|---|
| "tấn công", "hack" | GET + parse HTML/RSC, không khai thác lỗ hổng |
| "vượt tường phí" | Đọc lại dữ liệu server đã gửi cho client; không mua, không crack |
| "lách khoá" | Kiểm tra xem body chương có nằm trong payload dù bị cờ `isLocked` gate (đã biết: **không**) |
| "cookie" | Chuỗi cookie phiên của user, dán vào env `TTM_COOKIE` |
| "audio free" | Kiểm tra xem server có render `audioUrl` cho account của user không |
| "crawl" | Vòng lặp GET tuần tự, 1 luồng, nghỉ ≥2s |

---

## 5. Kỷ luật quy trình

1. Recon — lấy mẫu thô, lưu fixture vào `recon/`, ghi ngày/UA/có-cookie-không
2. Giả thuyết — phát biểu dạng kiểm chứng được
3. Bằng chứng — chạy script, dán output thật, không diễn giải thay số liệu
4. Sửa — thay đổi tối thiểu
5. Xác minh — bằng field/độ dài cụ thể
6. Ghi lại — cập nhật `FINDINGS.md`

Không bao giờ tuyên bố "đã lấy được" mà chưa có output chứng minh.

---

## 6. Điều cấm / bắt buộc

CẤM:
- Bịa endpoint, bịa tên field, bịa selector rồi viết code như đã xác minh
- Dùng `isLocked` làm bộ lọc để *né* bằng chứng — dùng làm nhãn trạng thái và báo cáo
- Kéo Playwright/Selenium khi GET thường còn chạy được
- Chạy song song nhiều luồng
- Tuyên bố "hợp pháp" như một kết luận pháp lý chắc chắn
- Cố ý vượt khoá nội dung hoặc hạng VIP

BẮT BUỘC:
- Lưu response thô vào `recon/` trước khi parse
- Ghi rõ độ dài body từng chương vào report
- Nghỉ 2s giữa các request
- Resume theo file đã có, không tải lại
- Ghi mọi giả thuyết sai vào `FINDINGS.md` (kể cả cái đã bỏ)

---

## 7. Kỹ thuật

- KISS: sửa ít nhất có thể để đạt mục tiêu
- Không placeholder, code chạy được nguyên khối
- Bằng chứng phải kèm: URL, độ dài, cờ trạng thái, đoạn trích 200 ký tự
- Thử trên 1 chương trước khi chạy cả truyện
- Chỉ dùng `requests` (+ `beautifulsoup4`/`lxml` nếu cần)

---

## 8. Dụng cụ

| Việc | File |
|---|---|
| Recon 1 chương / audio | `ttm_recon.py` |
| Tải chương + audio | `ttm_grab.py` |
| Kết luận, giả thuyết đã bỏ | `FINDINGS.md` |
| Fixture thô | `recon/` |
| Kết quả tải | `download/<slug>/{text,audio}/` |

---

## 9. Định nghĩa hoàn thành

- [x] `recon/report.json` có kết luận cho ≥3 chương (khoá + mở)
- [x] Kết luận ghi rõ: body có trong payload hay không, độ dài, cờ trạng thái
- [x] `ttm_grab.py` chạy được trên 1 chương thật, file ra ≥500 ký tự
- [ ] Audio: chứng minh được 1 URL .mp3 tải không cần cookie — **CHƯA ĐƯỢC**: cần cookie hạng VIP (`TTM_COOKIE`)
- [x] `FINDINGS.md` ghi cả giả thuyết đã bác bỏ
- [x] Chạy lại lần 2 không tải lại file đã có
