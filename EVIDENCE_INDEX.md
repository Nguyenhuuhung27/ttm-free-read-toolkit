# EVIDENCE INDEX — `ttm-free-read-toolkit`

Mục đích: nói rõ **mỗi file chứng minh điều gì**, và **không chứng minh điều gì**.
Tất cả evidence hiện có được capture **anonymous** trên production ngày 2026-11-14
(commit `2415a88`). **Không có** secret, cookie value, bearer token, session ID,
dữ liệu cá nhân, hay nội dung chương trả phí trong index này.

> ⚠️ Có **3 file** trong `download/` chứa **full-text chương miễn phí thật** của
> production (đã có từ commit `2959fa1`). Chúng là artifact của phiên trước,
> **không được dùng làm evidence cho audit này** và không được trích dẫn nội dung.
> Brief cấm lưu/phân phối nội dung trả phí; 3 chương này là chương mở, nhưng vẫn
> là nội dung production — nên để chủ repo quyết định giữ hay gỡ. Các test mới
> dùng **synthetic fixtures** thay thế.

---

## 1. Evidence JSON (máy đọc được)

| File | Chứng minh | KHÔNG chứng minh |
|---|---|---|
| `recon/control_audit.json` | 21 route qua/không qua gate; 10 biến thể đuôi path; so sánh ch.1 vs ch.4 (content/DOM/longest string); 11 API không có field body; 8 error response; security headers/CORS/cookie/cache | Không chứng minh entitlement của user đã đăng nhập; không chứng minh cache leak |
| `recon/entitlement_audit.json` | Bản chạy mẫu (7 chương TOC): 19 probe, 6 kênh, 7 API, 3× repeat, 7 cache-key variant, 5× RSC/HTML alternate | Bản đầy đủ là `entitlement_sweep.json` |
| `recon/entitlement_sweep.json` | **51/51 chương**: 48 khoá `body=0`, 3 mở có body, 0 inconsistent; `sections.cache.sessions = null` → chưa có 2 phiên thật | Không chứng minh cách ly cache giữa A/B (thiếu tài khoản) |
| `recon/passive_check.json` | Header của 8 API, 6 security headers, CORS, cache, retest gate, deployment fingerprint (`lastmod`, `access_gate_enabled=1`) | Không chứng minh cấu hình CDN thật |
| `recon/report.json` | Output `ttm_recon.py`: 4 chương, verdict `BODY_PRESENT`/`LOCKED_EMPTY`, TOC 51 | Chỉ anonymous |

## 2. Response thô (đã cắt 4 000 ký tự đầu)

| File | Chứng minh |
|---|---|
| `recon/audit/doc_1.html` | Chương MỞ: HTML render sẵn có `div.prose` |
| `recon/audit/doc_4.html` | Chương KHOÁ: placeholder, không `div.prose`, `content:""` |
| `recon/audit/error_400_nextauth.txt` | 400 generic, không stack/path |
| `recon/audit/error_404_api.txt`, `error_404_page.txt` | 404 không lộ buildId/path FS/stack |
| `recon/audit/error_405_unlock.txt` | 405 body rỗng |
| `recon/audit/error_bad_param.txt` | 500 → `{"error":"Internal error"}` (26 bytes), đã ẩn stack |
| `recon/audit/error_bad_chapter.txt`, `error_bad_search.txt` | Input xấu → response bình thường, không exception |
| `recon/audit/error_gate_error.txt` | Gate error không lộ lý do từ chối chi tiết |
| `recon/gate.html`, `recon/landing.html` | Form `POST /api/access-gate`; landing gate |
| `recon/doc_*.html`, `recon/doc_*_anon.html` | Fixture RSC của các chương 1–6, 26 |
| `recon/nghe_*.html`, `recon/nghe_*_anon.html` | Trang nghe: "Audio bị khóa"/"chưa có file audio", không `audioUrl` |
| `recon/doc26.html` | Chương 26 khoá: `content:""`, chunk `1b` là module ref |

## 3. Client bundle đã capture (1 dòng minify → trích `@byte offset`)

| File | Symbol / offset | Chứng minh |
|---|---|---|
| `recon/webpack.js`, `recon/main-app.js` | `__next_f`, `_next/static` | Next.js App Router, RSC flight stream |
| `recon/layout-8430bcd733497a62.js` | `@3175 useSession`, `@17970 /api/user/audio-remaining`, `@26281 /api/config` | Session & audio quota phía client |
| `recon/page-2936fb800ce950f1.js` | `@8506 isLocked`, `@9270 /api/chapter-errors`, `@12300 ChapterComments`, `@12532 useSession`, `@12724 /api/chapters/`, `@24900 POST /api/chapters/<id>/unlock`, `@27350 /api/reading-history`, `@27900 locked:Z`, `@31350 dangerouslySetInnerHTML` (cho `authorNote`), `@32528 /api/config` | Các route/object id **thật sự tồn tại** trong client; client chỉ render `locked` do server cấp |
| `recon/nghe_page.js` | `@4257 audioUrl`, `@5054 /api/listening-history`, `@21742 /api/chapter-errors` | Prop audio được truyền từ server component |
| `recon/726-*.js` | chunk dùng chung | Không chứa logic entitlement |

**Không có file nào trong repo là source code server** → mọi "code path" server
trong `NEXT_AUDIT.md` §2 đều là **Inferred**, không phải xác nhận từ mã nguồn.

## 4. Synthetic fixtures & tests (mới, không chứa dữ liệu thật)

| File | Vai trò |
|---|---|
| `tests/fixtures/README.md` | Mô tả 7 fixture, quy ước `SYNTHETIC-TEST-BODY` |
| `tests/make_fixtures.py` | Sinh lại fixture deterministic; tránh bash expand `$1b`/`$15` |
| `tests/fixtures/free_chapter.html`, `locked_chapter.html` | HTML giả: mở / khoá |
| `tests/fixtures/free_chapter.rsc`, `locked_chapter.rsc` | RSC thô giả: `$15` / `content:""` |
| `tests/fixtures/toc.html`, `headers_fixture.json`, `sessions_fixture.json` | TOC, header cache, 4 kịch bản A/B |
| `tests/test_audit_offline.py` | 37 test offline; khóa các invariant chống suy luận sai |
| `audit_classify.py` | Hàm thuần `content_state` / `cache_isolation_state` / `classify` / `redact` |

### 4b. Artifact đợt 2026-11-15 19:3x (5 ưu tiên A/B)

| File | Chứng minh | KHÔNG chứng minh |
|---|---|---|
| `ttm_staging_audit.py` | Harness fail-closed cho đúng 5 ưu tiên; từ chối production host; từ chối thiếu env/cookie trùng; mặc định chỉ GET; không log secret. WS2 phủ **6 endpoint** (thêm `/api/reading-history`); cờ `needs_review` chỉ bật khi A có dữ liệu session-specific **và** B nhận đúng body A | Không chứng minh lỗ hổng nào; **chưa từng chạy `--run` thành công** |
| `tests/test_staging_harness.py` | 21 unit test mock: prerequisite gating (8), 5 workstream (11), plan không lộ secret (2). Bao gồm kịch bản leak synthetic để chứng minh classifier bắt được, và 2 test chống tái phát lỗi logic WS2 (xem `FINDINGS.md` §14.6) | Không phải bằng chứng runtime; response là synthetic/mock |
| `tests/test_staging_e2e_local.py` | 2 test end-to-end: chạy `--run` thật (`main()` → Harness → WS1–WS5 → `flush()`) trên mock server `127.0.0.1:0`, `--out` trong thư mục tạm. Chứng minh đường chạy thật sinh evidence JSON đầy đủ (42 rows, 5 section, `confirmed_vulnerabilities=[]`), **không** lộ giá trị cookie, `needs_review` bắt đúng case cross-session, và **không** ghi file vào repo | Chứng minh **tính đúng đắn của công cụ đo**, KHÔNG phải bằng chứng về ứng dụng; nội dung phục vụ đều là synthetic |
| `recon/staging_plan.json` | **Bằng chứng trạng thái**: `ready=false`, `missing=7`, `sessions_fp={}`, `scope_ref=''`. Ghi lại chính xác prerequisite còn thiếu | Không chứa cookie/token (chỉ độ dài env); không phải output runtime |
| `FINDINGS.md` §14 | Source-level analysis 4 nhóm object + audio + matcher với `@byte offset`; bảng 5 finding đều `Unknown`; §14.6 ghi 2 khiếm khuyết của harness đã sửa | Không có exact server source line (repo không có source server) |

**Lưu ý:** `recon/staging_audit.json` (output của `--run`) **chưa tồn tại** — đó là
file sẽ xuất hiện khi có staging + 2 tài khoản được ủy quyền. Đừng nhầm
`staging_plan.json` với evidence runtime.

## 5. Tài liệu

| File | Nội dung |
|---|---|
| `NEXT_AUDIT.md` | Báo cáo đợt trước: scope, bản đồ kiến trúc, re-verify 6 giả thuyết, Unknown/prerequisite |
| `FINDINGS.md` §13–14 | §13 re-verification; **§14 đợt 5 ưu tiên A/B** — source-level analysis + 5 finding `Unknown` |
| `CONTROL_AUDIT.md` | Phân lớp gate/entitlement, retest F2, rà soát cấu hình (2026-11-14) |
| `ENTITLEMENT_AUDIT.md` | 3 lớp: server authz / content delivery / cache (2026-11-14) |
| `TESTPLAN.md` | Ma trận testcase có ủy quyền (cần 2 tài khoản) |
| `CLAUDE.md` | AI behavior contract của toolkit |
| `HANDOFF.md` | Trạng thái hiện tại, lệnh, exit code, bước tiếp theo |

## 6. Kiểm tra rò rỉ

Lệnh đã chạy trong đợt này (xem `HANDOFF.md`): `git grep` cho
`csrf-token=<hex>`, `session-token=`, `Bearer <token>`, `gh[pousr]_…`,
`TTM_COOKIE=<value>`, `Cookie: <value>` → **0 match**. Test
`TestClassificationRules::test_redact` xác nhận hàm che giá trị cookie/token.
Các file `download/` được giữ nguyên (không đọc, không trích, không sửa).
