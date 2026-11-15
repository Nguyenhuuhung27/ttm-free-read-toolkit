# Synthetic RSC / HTML fixtures for offline regression tests

**Tất cả nội dung trong thư mục này là giả (synthetic)**, được tạo tay để test
parser và logic phân loại. Không chứa nội dung chương thật, không chứa cookie,
token, session ID hay dữ liệu người dùng.

| File | Mô phỏng |
|---|---|
| `free_chapter.html` | Chương MỞ: `locked:false`, `content:"$1b"`, chunk `1b:T…` có body, DOM `div.prose` |
| `locked_chapter.html` | Chương KHOÁ: `locked:true`, `content:""`, không có chunk text, DOM placeholder |
| `free_chapter.rsc` | `text/x-component` thô, `content:"$15"`, chunk `15:T…` |
| `locked_chapter.rsc` | `text/x-component` thô, `content:""`, không chunk text |
| `toc.html` | `chapters[]` 3 mục: 1 mở, 2 khoá |
| `headers_fixture.json` | Header cache/CORS mẫu để test phân loại |
| `sessions_fixture.json` | 4 kịch bản A/B/A/anon để test `cache_isolation_state` |

Quy ước: mọi body giả bắt đầu bằng `SYNTHETIC-TEST-BODY`, dễ nhận diện nếu lọt
vào report thật.
