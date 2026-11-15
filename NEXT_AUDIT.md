# NEXT_AUDIT — tiếp tục đánh giá `ttm-free-read-toolkit`

**Ngày:** 2026-11-15 | **Commit gốc khi bắt đầu:** `2415a88` | **Branch:** `main`
**Môi trường runtime:** **không có** staging, không có 2 tài khoản test được ủy quyền
(`TTM_COOKIE_A` / `TTM_COOKIE_B` / `TTM_COOKIE` đều rỗng, đã kiểm tra bằng `${#VAR}`).

> **Kết luận chính: KHÔNG có lỗ hổng authorization / entitlement-isolation /
> cache-isolation nào được chứng minh.** Đây là một clean result hợp lệ theo
> Definition of Done của brief. Báo cáo này không "nâng cấp" bất kỳ quan sát cấu
> hình nào thành finding khai thác được.

---

## 1. Scope và giới hạn

| Mục | Trạng thái |
|---|---|
| Đọc repo, commit history, toàn bộ docs/scripts/evidence | ✅ Hoàn tất |
| Re-verify 6 giả thuyết cũ bằng evidence JSON hiện có | ✅ Hoàn tất (mục 3) |
| Source-level review của **ứng dụng** | ⚠️ **Không thể**: repo KHÔNG chứa source server |
| Workstream 2 (2 tài khoản A/B) | ❌ **not verified at runtime** — thiếu prerequisite |
| Workstream 3 (object-level authz) | ❌ **not verified at runtime** — cần test accounts + test records |
| Workstream 4 (cache isolation) | ⚠️ Review header offline ✅; runtime ❌ |
| Workstream 5 (audio / alternate representations) | ⚠️ Review bundle offline ✅; runtime ❌ |
| Regression tests offline, deterministic | ✅ 37/37 pass |

**Quy tắc áp dụng nghiêm:** không gọi network trong đợt audit này; không POST mutate;
không enumerate ID; không đoán endpoint/field; không đọc file cấu hình/bí mật; không
suy luận vulnerability từ HTTP 200, UI change, middleware bypass hay metadata.

---

## 2. Bản đồ kiến trúc (từ evidence trong repo, không phải source server)

⚠️ **Hạn chế nền tảng:** repo là **audit toolkit**, không phải mã nguồn ứng dụng.
Không có file `.ts/.tsx` server, không có route handler, không có Prisma schema,
không có `middleware.ts`, không có cấu hình CDN. Vì vậy **mọi "code path" dưới đây
là Inferred từ client bundle đã capture + RSC payload**, không phải xác nhận từ
mã nguồn. Không thể trích dẫn "exact line" của server code — chỉ trích được
byte offset trong bundle client (mỗi bundle là 1 dòng đã minify, nên dùng `@offset`).

| Thành phần | Bằng chứng trong repo | Trạng thái |
|---|---|---|
| Framework / build | `recon/webpack.js`, `recon/main-app.js`, `recon/landing.html` (`__next_f`, `_next/static/chunks/...`), `X-Powered-By: Next.js` trong `recon/control_audit.json` → `sections.errors.cases[].headers` | Observed (client + header) |
| Session resolution (client) | `recon/layout-8430bcd733497a62.js` `@3175` `useSession`; `recon/page-2936fb800ce950f1.js` `@12532` `useSession`, `@27900` `"authenticated"===status` | Observed (client only) |
| Session endpoints | `/api/auth/{session,providers,csrf}` — `recon/passive_check.json` (`api`), `FINDINGS.md` §7 | Observed (anonymous responses) |
| Entitlement decision | **Server component**: props `locked`, `remainingDailyUnlocks`, `nextChapterLocked` trong `recon/control_audit.json` → `sections.content.chapters.locked.props`; client nhận `locked:Z` tại `recon/page-2936fb800ce950f1.js` `@27900` | **Inferred** (server-side, từ RSC props; không có source) |
| Chapter metadata | `chapters[]` (`chapterNumber/title/hasAudio/isLocked`) trong payload `/doc/<N>.html` — `ttm_recon.py::parse_chapters` | Observed |
| Chapter body retrieval | `content` = tham chiếu `$1b` (HTML) / `$15` (RSC), chunk `T<hex>,<text>`; client render `div.prose` `@31350` `recon/page-2936fb800ce950f1.js` | Observed (wire format) |
| Audio authorization (client) | `recon/nghe_page.js` `@4257` prop `audioUrl`, `@5054` `/api/listening-history`; `recon/layout-8430bcd733497a62.js` `@17970` `/api/user/audio-remaining` | Observed (client symbols) |
| Audio authorization (server) | `"Audio bị khóa"` trong `recon/nghe_1_anon.html`; không có `audioUrl` trong 11 API — `recon/control_audit.json` | Observed (anonymous), **Unknown** cho tài khoản VIP |
| Unlock endpoint | `recon/page-2936fb800ce950f1.js` `@24900` `POST /api/chapters/<id>/unlock` | Observed (client) — **chưa test POST** |
| Object-scoped endpoints | `@27350` `/api/reading-history`, `@9270` `/api/chapter-errors`, `@12724` `/api/chapters/<id>/comments`, `@17970` `/api/user/audio-remaining` | Observed (client) — chưa test ownership |
| Caching / headers | `recon/passive_check.json` (`api`, `cache`), `recon/control_audit.json` (`sections.config`), `recon/entitlement_sweep.json` (`sections.cache`) | Observed (headers) — **không có cấu hình CDN trong repo** |
| Access gate | `307 → /khong-co-pass`; form `POST /api/access-gate` — `recon/gate.html`, `recon/control_audit.json` → `sections.gate` | Observed (redirect), matcher **Inferred** |

**Dòng dữ liệu (Inferred):**
```
request → [L1 middleware gate: 307 unless path has dot / is /api or static]
        → Next.js route /truyen/[slug]/doc/[chapter]  (server component)
        → server component: resolve session → compute locked / remainingDailyUnlocks
        → locked=true  → content="" (không có chunk text), render placeholder
          locked=false → content="$1b" + chunk T<hex>,<body>, render div.prose
        → response HTML / (RSC:1 → text/x-component)
```
`Cache-Control` và `Vary` được set (2 lần ở một số route) — nguồn cụ thể
(route handler hay middleware) **Unknown** do thiếu source.

---

## 3. Re-verify 6 giả thuyết cũ

Mỗi dòng ghi rõ file + commit + lệnh + môi trường. Commit `2415a88` chứa toàn bộ
evidence; các test mới chạy offline bằng `python -m unittest discover -s tests -v`.

| # | Giả thuyết | Kết luận | Bằng chứng (file · test) | Môi trường |
|---|---|---|---|---|
| H1 | Client-side extension bypass middleware/presentation gate | **Observed** (anonymous, 2026-11-14), **chưa re-verify trên build hiện tại** | `recon/control_audit.json` → `sections.gate.dot_suffix_probe`: 1/10 bị gate (path không dấu chấm), 8× 200, 1× 404 (`.html/x`). Test `TestEvidenceIntegrity::test_gate_dot_suffix_probe_has_10_rows` | Anonymous, production responses đã capture; **không test lại hôm nay** |
| H2 | Server-side entitlement checks vẫn hiệu lực | **Observed (anonymous)**: 19/19 thử tự gán quyền thất bại; **Unknown** cho tài khoản đã mở khoá | `recon/entitlement_sweep.json` → `sections.server_authorization`; test `test_19_entitlement_probes_all_locked` | Anonymous only; không có A/B |
| H3 | Body chương khoá vắng trong HTML/RSC/prefetch | **Observed (anonymous)**: 48/48 chương khoá `body=0`; 6 kênh nhất quán; 51/51 TOC khớp | `recon/entitlement_sweep.json` → `sections.content_delivery`; tests `test_sweep_51_chapters_all_consistent`, `test_locked_chapter_has_no_body_in_evidence`, `TestInspectChannels` (synthetic) | Anonymous + synthetic fixtures |
| H4 | Anonymous audio không nhận `audioUrl` được bảo vệ | **Observed (anonymous)**: 0/11 API có `audioUrl`; `/nghe` render "Audio bị khóa". **Unknown** cho VIP | `recon/control_audit.json` → `sections.content.api`, `recon/nghe_1_anon.html`; test `test_apis_have_no_content_field` | Anonymous only |
| H5 | Cache leakage chưa từng được chứng minh | **Đúng — vẫn chưa chứng minh**. `sessions is null`, 3× `DYNAMIC`, không `Age`/`ETag` | `recon/entitlement_sweep.json` → `sections.cache`; tests `test_no_real_sessions_recorded`, `test_cache_no_hit_in_evidence`, `TestCacheIsolationClassifier` | Anonymous + synthetic; **không có A/B** |
| H6 | 48/51 khoá `body=0`; 19/19 mô phỏng thất bại | **Observed**, khớp chính xác | `recon/entitlement_sweep.json`; tests `test_sweep_51_chapters_all_consistent`, `test_19_entitlement_probes_all_locked` | Offline re-computation |

**Không có giả thuyết nào bị contradicted.** Không có giả thuyết nào được nâng
thành "confirmed vulnerability".

### Phân loại theo brief

| Nhãn | Nội dung |
|---|---|
| **Observed** | H1 (trên build 2026-11-14), H2/H3/H4/H5/H6 ở mức anonymous; header cache/CORS/cookie như `FINDINGS.md` §11–12; 37/37 test pass |
| **Inferred** | Matcher middleware loại trừ path có dấu chấm; entitlement nằm ở server component; `Cache-Control` trùng do route + middleware; `.css/.png` là "cache deception surface" |
| **Unknown** | Entitlement của tài khoản A đã mở khoá; object-level ownership; cache isolation giữa A/B; logout/expiry/revoke; audio authorization cho VIP; nguồn gốc header cache; trạng thái build 2026-11-15 |

---

## 4. Cấu hình bảo mật đã review (hardening, KHÔNG phải finding)

| Quan sát | Evidence | Phân loại |
|---|---|---|
| 6 security headers vắng (HSTS/CSP/XFO/XCTO/Referrer-Policy/Permissions-Policy) | `recon/passive_check.json` → `security_headers` | Hardening lead; cần thêm điều kiện khai thác |
| CORS không reflect `Origin` (5 origin + preflight 204 không `ACAO`) | `recon/control_audit.json` → `sections.config.cors` | **Đạt** — không thiếu sót |
| Cookie `__Host-` / `__Secure-` đúng flag | `sections.config.cookies` | **Đạt** (anonymous CSRF cookie); session cookie thật chưa kiểm tra |
| `/api/config`: `public, s-maxage=300` lẫn `private, no-store`; 5 route header trùng | `sections.config.cache` | Review lead; `cf-cache-status: DYNAMIC` → chưa có cache hit |
| `Vary` thiếu `Cookie` | `sections.config.cache` | **Review lead, không phải proof** theo đúng brief Workstream 4 |
| `.css`/`.png` trả HTML chương (127 303 bytes) với `cf=BYPASS` | `recon/entitlement_sweep.json` → `sections.cache.key_variants` | Bề mặt cần theo dõi; chưa có response lọt sang phiên khác |
| 500 `{"error":"Internal error"}`, 405 rỗng, 400 generic; không stack/PHP/path FS | `recon/audit/error_*.txt` | **Đã ẩn** thông tin nhạy cảm (F2) |
| `?limit` thiếu validate (500 / không clamp) | `recon/audit/error_bad_param.txt`, `CONTROL_AUDIT.md` §4 | Robustness, không phải info disclosure |

---

## 5. Câu hỏi chưa trả lời & prerequisite chính xác

**"not verified at runtime"** cho: session/entitlement isolation, object-level
authorization, cache isolation, audio authorization, logout/expiry/revoke.

Thiếu **đúng 4 thứ** (không hơn, không kém):

1. **Staging environment** được ủy quyền (hostname/base URL), tách khỏi production.
   Repo không có file cấu hình deployment nào; mọi evidence hiện tại là production
   anonymous 2026-11-14.
2. **Hai tài khoản test độc lập** A (có entitlement tới test chapter) và B (không có),
   cấp dưới dạng `TTM_COOKIE_A` / `TTM_COOKIE_B` (chỉ đọc qua env, không commit).
3. **Một test chapter có nội dung synthetic** hoặc được chủ sở hữu phê duyệt rõ ràng,
   kèm `slug`, `chapterNumber`, `chapterId`. Không dùng chương thật.
4. **Xác nhận phạm vi cho phép mutate** (POST `/api/chapters/<id>/unlock`,
   `/api/reading-history`, comments) nếu muốn chạy Workstream 3 đầy đủ.

Thiếu (1)–(3) → không thể chạy `ttm_entitlement_audit.py --sessions` một cách có
ý nghĩa: nếu A vẫn `locked:true` thì test vô nghĩa (đã encode trong
`audit_classify.cache_isolation_state` → `UNKNOWN_A_NOT_ENTITLED`).

---

## 6. Regression tests đã thêm

`tests/test_audit_offline.py` — 37 test, `python -m unittest discover -s tests -v`
→ `OK`, exit 0. Dùng `tests/fixtures/*` (synthetic, sinh bởi
`tests/make_fixtures.py`) + evidence JSON có sẵn. Không network, không credential.

Nhóm test: parser RSC (9), kênh HTML/RSC (5), quy tắc phân loại & redaction (7),
cache isolation classifier (5), integrity của evidence cũ (11).

Các bất变 (invariant) được khóa cứng:
- `content_state()` **không nhận HTTP status** → chống suy luận từ 200 (test
  `test_http_status_is_not_an_input`).
- `cache_isolation_state([])` → `UNKNOWN_NO_AUTHORIZED_SESSIONS`; `Vary` thiếu
  `Cookie` **không bao giờ** tự kết luận leak.
- Locked fixture: `body=0`, `dom=0`, không `audioUrl`.
- HTML và RSC free body cùng độ dài; UTF-8 tiếng Việt không mojibake.
- Evidence cũ: 51 chương / 48 khoá / 19 probe / 11 API / 10 dot-probe / 8 error case.

---

## 7. Bước tiếp theo có thể kiểm chứng

1. Cấp (1)–(3) ở mục 5, rồi chạy trên **staging**:
   `TTM_COOKIE_A=... TTM_COOKIE_B=... python ttm_entitlement_audit.py --sessions`
   và đọc `B_received_A_content` + bảng A→B→A→anon.
2. Workstream 3: dùng **non-content test objects** (reading progress, favorites,
   listening history) với **test records do chính A/B tạo**. Không enumerate ULID.
3. Workstream 4: gắn `Age`/`ETag`/`Last-Modified` và `cf-cache-status` vào log;
   review cấu hình CDN thật nếu chủ sở hữu cung cấp.
4. Workstream 5: trên staging, kiểm tra `audioUrl` chỉ xuất hiện khi A có entitlement
   và không xuất hiện cho B; dùng synthetic audio asset.
5. Re-verify H1 trên build hiện tại kèm fingerprint (`sitemap lastmod`, chunk hash)
   — evidence cũ đã 1 ngày tuổi và deployment từng đổi 3 lần trong một phiên.

---

## 8. Evidence index

Xem `EVIDENCE_INDEX.md`. Chi tiết lệnh/exit code/xem `HANDOFF.md`.
Cập nhật finding (không tạo claim trùng) nằm tại `FINDINGS.md` §13.
