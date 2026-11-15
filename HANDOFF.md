# HANDOFF — trạng thái bàn giao

**Cập nhật lần cuối:** 2026-11-15 ~20:5x GMT+7
**Repo:** https://github.com/Nguyenhuuhung27/ttm-free-read-toolkit (public)
**Branch:** `main` | **Commit khi bắt đầu đợt này:** `c301dac`
**Nhiệm vụ hiện tại:** 5 ưu tiên A/B session/object/cache/audio/matcher — **sửa harness trước khi đánh giá runtime**
**Nhiệm vụ trước:** `D:\Downloads\ttm_free_read_toolkit_next_audit.md`

> ⚠️ **Mục 0 là trạng thái HIỆN TẠI.** Mục 1–7 bên dưới là handoff của đợt
> 18:5x (vẫn còn giá trị lịch sử, một vài con số đã cũ — được ghi chú rõ).

---

## 0. Trạng thái hiện tại (đợt 19:3x)

### 0.1 Dữ kiện

| Mục | Giá trị |
|---|---|
| Network calls tới ứng dụng | **0** (không gọi production, không có staging) |
| `TTM_STAGING_URL` / `TTM_BASE_URL` / `STAGING_URL` / `BASE_URL` | đều độ dài 0 |
| `TTM_ALLOWED_STAGING_HOSTS` (env mới — allowlist exact-match) | độ dài 0 |
| `TTM_COOKIE` / `TTM_COOKIE_A` / `TTM_COOKIE_B` | đều độ dài 0 |
| `TEST_CHAPTER_ID` / `TEST_CHAPTER_SLUG` / `TTM_TEST_SLUG` | đều độ dài 0 |
| File cấu hình deployment trong repo | **0** (`.env*`, `next.config*`, `middleware*`, `vercel.json`, `wrangler*`, `docker-compose*`) |
| Confirmed vulnerabilities | **0** |
| 5 ưu tiên | **not verified at runtime**; đã có harness + **66 unit test** (62 mock + 4 end-to-end local) |
| Test suite | **103/103 OK** (37 cũ + 62 harness + 4 e2e), exit 0 |
| Khiếm khuyết harness đã sửa | **9** (H-1…H-3 ở §14.6; D-1…D-6 ở §14.7) |

### 0.2 Files đợt này

| File | Loại | Mục đích |
|---|---|---|
| `ttm_staging_audit.py` | sửa lớn | Harness fail-closed cho 5 ưu tiên: WS1 A/B isolation (fingerprint nội dung), WS2 object authz (6 endpoint + phase 2 tạo record synthetic), WS3 cache isolation, WS4 audio entitlement, WS5 matcher + fingerprint. **Allowlist exact-match**, **abort 403/429**, **write gating cứng** |
| `audit_classify.py` | sửa | Thêm helper thuần: `normalize_content`, `content_fingerprint`, `audio_signals`, `audio_entitlement_state`, `record_fingerprint`, `object_authz_state`; `cache_isolation_state` ưu tiên `content_sha` |
| `tests/test_staging_harness.py` | viết lại | **62 unit test mock**: allowlist strict, abort/expect-deny, write gating, credential guard, fingerprint nội dung, audio verdict, object-authz verdict, WS2 phase 2 |
| `tests/test_staging_e2e_local.py` | viết lại | **4 test end-to-end**: `--run` thật trên mock server `127.0.0.1:0`, evidence ra thư mục tạm, có cả biến thể `--allow-mutate` |
| `recon/staging_plan.json` | mới | Bằng chứng trạng thái: `ready=false`, `missing=8`, không chứa secret |
| `FINDINGS.md` | sửa §14 | Source-level analysis + 5 finding đều `Unknown`; thêm §14.6 (H-1…H-3) và §14.7 (D-1…D-6) |
| `EVIDENCE_INDEX.md` | sửa | Thêm mục 4b, phân biệt `staging_plan.json` với `staging_audit.json` (chưa tồn tại) |
| `HANDOFF.md` | sửa | Thêm mục 0 này |

**Chỉnh sửa nhỏ sau commit `9fd41c1` (commit `e9d3ced` + đợt này):**
- `tests/test_staging_harness.py`: test `--plan` dùng mock capture thay vì ghi
  file thật → chạy suite không làm dirty `recon/staging_plan.json`.
- `ttm_staging_audit.py`: `--plan` mặc định **chỉ in ra stdout**; thêm
  `--write-plan` khi muốn refresh evidence artifact. Thêm 1 unit test cho hành
  vi không ghi file → suite **56/56**.

**Sửa khiếm khuyết harness vòng 20:0x (không gọi network, xem `FINDINGS.md` §14.6):**
- `ttm_staging_audit.py` WS2: thêm `GET /api/reading-history` (ưu tiên 2 nêu rõ
  "reading history" nhưng WS2 bỏ sót; client chỉ lộ call site POST `@27459`,
  GET list nằm ở bundle chưa capture). WS2 giờ phủ **6 endpoint**.
- `ttm_staging_audit.py` WS2: sửa cờ `needs_review` vốn viết
  `a_bytes != b_bytes and b_hash == a_hash` — hai điều kiện loại trừ nhau nên
  cờ **không bao giờ bật**. Nay tách `a_has_session_specific_data` (A khác anon)
  và `b_got_a_data` (B nhận đúng body A); cờ chỉ bật khi cả hai đúng.
- +2 unit test chống tái phát → suite **58/58**.

**Sửa khiếm khuyết harness vòng 20:2x — D-1…D-6 (xem `FINDINGS.md` §14.7):**
- **D-1** `staging_host_ok()` dùng **substring matching** → host `evil-staging.attacker.com`
  lọt qua. Nay dùng **exact-match allowlist** qua env mới `TTM_ALLOWED_STAGING_HOSTS`;
  production bị chặn kể cả khi nằm trong allowlist.
- **D-2** 403/429 chỉ `print()` rồi chạy tiếp → nay `AbortRun`, dừng ngay, flush
  evidence, exit **4**. `429` luôn dừng; `403` dừng trừ probe `expect_deny`
  (anon bị từ chối là kết quả mong đợi).
- **D-3** `--allow-mutate` chỉ kiểm ở `main()` → nay `Harness.post()` tự ném
  `WriteNotAuthorized` trừ khi có **cả hai** cờ (`--allow-mutate` **và**
  `TTM_MUTATE_AUTHORIZED=1`). Mọi write được ghi vào `evidence.writes`.
- **D-4** WS1/WS3 so sánh **hash toàn response** (metadata động làm sai) → nay so
  sánh **fingerprint nội dung được bảo vệ**, độc lập metadata. Raw response vẫn
  không ghi ra evidence.
- **D-5** WS4 coi "cả hai đều không có audio" là kết luận thành công → nay A thiếu
  audio là `UNKNOWN_A_NO_AUDIO`, B có audio là `OBSERVED_NEEDS_REVIEW`. Phát hiện cả
  thuộc tính `audioUrl` lẫn media reference; URL không bao giờ được lưu.
- **D-6** WS2 chỉ GET → nay có **phase 2** (chỉ khi được ủy quyền): A tạo record
  synthetic, kiểm tra B đọc/sửa được không, anon có bị từ chối không, A còn truy
  cập được không.
- Thêm: credential guard (session chỉ tạo sau khi verify host; mỗi request kiểm tra
  lại host; path phải bắt đầu bằng `/`), exit code `0/3/4`.
- +25 unit test + 2 test e2e → suite **103/103**.

**Bổ sung vòng 20:1x — end-to-end (H-3, xem `FINDINGS.md` §14.6):**
- `tests/test_staging_e2e_local.py`: chạy `--run` thật (`main()` → `Harness` →
  WS1–WS5 → `flush()`) trên mock server `http.server` `127.0.0.1:0` (port tự
  chọn, không domain ngoài), `--out` trỏ thư mục tạm.
- Kết quả: **42 rows**, evidence JSON đủ 5 section, `confirmed_vulnerabilities=[]`,
  **giá trị cookie không xuất hiện** trong file, `needs_review` bắt đúng case
  cross-session (fix H-2 được kiểm chứng end-to-end), **không** ghi file vào `recon/`.
- Suite: **60/60**.

**Không sửa:** `ttm_recon.py`, `ttm_grab.py`, `ttm_passive_check.py`,
`ttm_control_audit.py`, `ttm_entitlement_audit.py`, `audit_classify.py`, `NEXT_AUDIT.md`,
`CONTROL_AUDIT.md`, `ENTITLEMENT_AUDIT.md`, `TESTPLAN.md`, `CLAUDE.md`,
toàn bộ `recon/*` cũ, toàn bộ `download/*`, `tests/test_audit_offline.py`,
`tests/fixtures/*`. → Không lặp offline test cũ thừa, giữ nguyên evidence.

### 0.3 Commands & exit codes (đợt này)

| # | Command | Exit | Kết quả |
|---|---|---|---|
| 1 | `git branch --show-current && git rev-parse --short HEAD && git status --short` | 0 | `main`, `93ebbd1`, sạch |
| 2 | `${#VAR}` cho 11 biến env + `env \| grep -iE 'staging\|test_\|^TTM_\|base_url'` | 0 | Tất cả prerequisite = 0; chỉ có `WECOM_MEDIA_UPLOAD_BASE_URL` (không liên quan) |
| 3 | `find . -maxdepth 2 -type f \( -name '*.env*' -o … \)` | 0 | 0 file cấu hình deployment |
| 4 | `python -c "…trích /api/ call site từ 4 bundle…"` | 0 | 10 call site, có `@byte offset` |
| 5 | `python -c "…inventory endpoint toàn recon…"` | 0 | 21 endpoint dạng literal |
| 6 | `python -c "…đếm userId/owner/user.id…"` | 0 | `userId × 0`, `owner × 0` trong 3 bundle |
| 7 | `python ttm_staging_audit.py --plan` | **3** | In kế hoạch, `ready=false`, **0 request** (exit 3 = chưa sẵn sàng, expected) |
| 8 | `python ttm_staging_audit.py --run` | **3** | `PREREQUISITES NOT MET`, liệt kê 7 env thiếu, **0 request** |
| 9 | `TTM_STAGING_URL=https://tieuthuyetmang.com … --run` | **3** | `TU CHOI: host production`, **0 request** |
| 10 | `python -m unittest discover -s tests -v` (lần 1) | **1** | 8 errors: mock `stub_harness` đọc env thật → `KeyError: TTM_COOKIE_A` |
| 11 | `python -m unittest discover -s tests -v` (lần 2) | **1** | 3 fail + 1 error: body fixture 151 < ngưỡng 200; fallback mock trả nhầm; `ws5` dùng sai key `status_code`; assertion note quá chặt |
| 12 | `python -m unittest discover -s tests -v` (lần 3) | **0** | `Ran 55 tests … OK` |
| 12b | Sau khi sửa side-effect (lần 4, có thêm 1 test) | **0** | `Ran 56 tests … OK` |
| 12c | Vòng 20:0x: bổ sung WS2 reading-history + sửa cờ `needs_review` (+2 test) | **0** | `Ran 58 tests … OK` |
| 12d | Vòng 20:1x: thêm end-to-end local (+2 test) | **0** | `Ran 60 tests … OK` |
| 12e | Vòng 20:2x: sửa D-1…D-6, viết lại 2 file test (+43 test) | **0** | `Ran 103 tests … OK` |
| 13 | `python -m unittest tests.test_audit_offline` | 0 | `Ran 37 tests … OK` |
| 13b | `python -m unittest tests.test_staging_e2e_local` | 0 | `Ran 4 tests … OK` (evidence ra thư mục tạm) |
| 14 | `python -m unittest tests.test_staging_harness` | 0 | `Ran 62 tests … OK` (trước: 21) |
| 15 | `python -m compileall -q . -x '(__pycache__|\.git)'` | 0 | Không lỗi |
| 16 | `git diff --check` / secret scan | 0 / 0 matches | Sạch |
| 17 | `python ttm_staging_audit.py --plan` (sau D-1) | **3** | Liệt kê **8** env thiếu (thêm `TTM_ALLOWED_STAGING_HOSTS`), **0 request** |
| 18 | `TTM_STAGING_URL=https://evil-staging.example.test … --run` | **3** | `TU CHOI: host ... khong co trong allowlist (exact match)`, **0 request** — trước D-1 host này lọt qua |

**Các lỗi đã fix (ghi lại để không lặp):** `stub_harness` phải `mock.patch.dict`
env giả; fixture body cần > 200 ký tự để classifier coi A là entitled (dùng
`FREE_HTML_LONG` = fixture + padding synthetic); vòng lặp matcher probe không
được ghi đè key `.html` của doc path; `ws5` đọc `rec["status"]` không phải
`status_code`; note "không kết luận vulnerability" là đúng nên test kiểm tra
cụm phủ định thay vì cấm từ "vulnerability"; **lambda trong vòng lặp phải bind
`session` ngay** (`lambda url, _s=s, **kw:`) nếu không cả 3 session sẽ trỏ tới
session cuối (anon) — đây là lý do các test WS trước đó trả về response rỗng.

### 0.4 Test results

```
Ran 103 tests in 5.500s
OK
```
- `tests/test_audit_offline.py` **37/37** (không sửa, chạy 1 lần trong suite đầy đủ)
- `tests/test_staging_harness.py` **62/62** — allowlist strict + abort + write gating
  + credential guard (18), fingerprint nội dung (2), audio signals & verdict (9),
  object-authz verdict (4), WS2 phase 2 (4), 5 workstream còn lại (25)
- `tests/test_staging_e2e_local.py` **4/4** — `--run` end-to-end trên `127.0.0.1`,
  gồm biến thể `--allow-mutate` và biến thể thiếu `TTM_MUTATE_AUTHORIZED` (exit 3,
  0 request)

Repo không có `pyproject.toml` / `package.json` / Makefile / CI → không có
build/lint chính thức; dùng `compileall`. Không cài dependency mới.

### 0.5 Runtime verification

> **"not verified at runtime"** cho cả 5 ưu tiên.

**0 request tới ứng dụng**. Mọi "Observed" trong `FINDINGS.md` §14 là tái đọc
evidence/client bundle có sẵn, không phải quan sát mới. Priority 5
("re-verify middleware matcher against current deployment") **chưa thực hiện**
vì yêu cầu dùng staging; không gọi production để thay thế.

**Prerequisite còn thiếu (đúng 4):**
1. Staging URL được ủy quyền, host có dấu hiệu staging (harness từ chối
   `*.tieuthuyetmang.com`), `TTM_STAGING_URL`.
2. Hai phiên độc lập `TTM_COOKIE_A` (có entitlement) / `TTM_COOKIE_B` (không có),
   phải **khác nhau** — không commit giá trị.
3. Test chapter **synthetic**: `TTM_TEST_SLUG`, `TTM_TEST_CHAPTER`,
   `TTM_TEST_CHAPTER_ID`, `TTM_TEST_STORY_ID`.
4. `TTM_MUTATE_AUTHORIZED=1` + `--allow-mutate` nếu muốn test ownership trên
   write path (`POST /api/reading-history`, comments, unlock). Mặc định chỉ GET.

`TTM_SCOPE_REF` (mã tham chiếu ủy quyền) là optional, chỉ ghi vào evidence.

### 0.6 Next verifiable step

```bash
export TTM_STAGING_URL='https://staging.example.test'   # KHONG phai production
export TTM_COOKIE_A='<session A>'                       # KHONG commit
export TTM_COOKIE_B='<session B>'                       # KHONG commit
export TTM_TEST_SLUG='<synthetic-slug>'
export TTM_TEST_CHAPTER='1'
export TTM_TEST_CHAPTER_ID='<synthetic-chapter-id>'
export TTM_TEST_STORY_ID='<synthetic-story-id>'
export TTM_SCOPE_REF='<authorization-ticket>'

python ttm_staging_audit.py --plan    # phai ra exit 0 (ready=true)
python ttm_staging_audit.py --run     # -> recon/staging_audit.json
python -m unittest discover -s tests -v
```

Đọc `recon/staging_audit.json`:
- `ws1.A_entitled == true` mới có ý nghĩa; nếu `false` → A chưa có entitlement,
  mọi kết luận isolation là `UNKNOWN_A_NOT_ENTITLED`.
- `ws1.B_received_A_body` / `ws3.classifier_result` — chỉ
  `OBSERVED_CROSS_SESSION_LEAK` mới được phép nâng thành finding.
- `ws2.objects[*].needs_review` — cần tạo test records của A trước khi kết luận
  IDOR (yêu cầu mutate scope).
- `ws4.audio_state` — so sánh sự có mặt `audioUrl`/media reference, không lưu URL.
- `ws1.content_fingerprints` / `ws3.content_sha_A|B|A_again` — so sánh **nội dung
  được bảo vệ**, không phải hash toàn response.
- `ws5.fingerprint` — gắn kết quả matcher vào đúng build (`sitemap`/`config` hash).

### 0.7 Rủi ro / lưu ý

- `recon/staging_audit.json` **chưa tồn tại**; `recon/staging_plan.json` chỉ là
  bằng chứng "chưa đủ prerequisite". Đừng nhầm hai file này.
- Repo **public** vẫn chứa 3 file `download/…/*.md` full-text chương miễn phí
  production — không đọc/sửa/xoá trong đợt này; chủ repo quyết định.
- Source-level analysis dùng **byte offset** trong bundle minify, không phải
  exact line của server source (repo không có server source).
- `FINDINGS.md` §14.2 ghi rõ tín hiệu "không thấy `userId`/`owner` param" là
  **ủng hộ** session-scoping, **không phải** bằng chứng server kiểm tra ownership.

---

## 1. Trạng thái hiện tại (exact) — *bản 18:5x, đã lỗi thời, xem mục 0*

| Mục | Giá trị |
|---|---|
| Runtime environment | **Không có staging**. `TTM_COOKIE=0`, `TTM_COOKIE_A=0`, `TTM_COOKIE_B=0` (độ dài env, kiểm tra bằng `${#VAR}`) |
| Network calls trong đợt này | **0**. Toàn bộ là offline review + synthetic tests |
| Ứng dụng | Không có source server trong repo; chỉ có client bundle đã capture |
| Build fingerprint trong evidence | `sitemap_lastmod=2026-11-14T06:31:36.718Z`, `access_gate_enabled="1"` — **đã 1 ngày tuổi** |
| Confirmed vulnerabilities | **0** (clean result) |
| Hardening leads | 6 security headers vắng; `Cache-Control` mâu thuẫn/trùng; `Vary` thiếu `Cookie`; `limit` thiếu validate; `.css/.png` trả HTML |
| Unknown | Entitlement của A đã mở khoá; object-level ownership; cache isolation A/B; logout/expiry/revoke; audio VIP; build 2026-11-15 |

---

## 2. Files changed / created

| File | Loại | Mục đích |
|---|---|---|
| `NEXT_AUDIT.md` | mới | Báo cáo: scope, bản đồ kiến trúc, re-verify 6 giả thuyết, phân loại Observed/Inferred/Unknown, prerequisite còn thiếu |
| `EVIDENCE_INDEX.md` | mới | Index từng file evidence + điều nó chứng minh / không chứng minh; cảnh báo 3 file `download/` |
| `FINDINGS.md` | **sửa §13** | Cập nhật finding theo format chuẩn (severity rationale, component, prerequisites, steps, expected/actual, evidence, impact, remediation). Không tạo claim trùng §1–12 |
| `HANDOFF.md` | mới | File này |
| `audit_classify.py` | mới | Hàm thuần: `content_state`, `cache_isolation_state`, `classify`, `redact`. Encode brief rule 6 (không nhận HTTP status) |
| `tests/test_audit_offline.py` | mới | 37 unittest: RSC parser (9), channels (5), classification/redaction (7), cache classifier (5), evidence integrity (11) |
| `tests/make_fixtures.py` | mới | Sinh lại fixture deterministic (tránh bash expand `$1b` → `b`) |
| `tests/fixtures/README.md` | mới | Mô tả 7 synthetic fixture |
| `tests/fixtures/free_chapter.html`, `locked_chapter.html` | mới | HTML giả mở / khoá |
| `tests/fixtures/free_chapter.rsc`, `locked_chapter.rsc` | mới | RSC thô giả `$15` / `content:""` |
| `tests/fixtures/toc.html`, `headers_fixture.json`, `sessions_fixture.json` | mới | TOC, header cache, 4 kịch bản A/B |
| `.gitattributes` | mới | Fixture `.rsc`/`.html` chứa **CRLF cố ý** để test parser → đánh dấu `-text -whitespace` để git không normalize, không báo trailing whitespace, và giữ deterministic khi checkout ở máy khác |

**Không sửa:** `ttm_recon.py`, `ttm_grab.py`, `ttm_passive_check.py`,
`ttm_control_audit.py`, `ttm_entitlement_audit.py`, `CLAUDE.md`, `CONTROL_AUDIT.md`,
`ENTITLEMENT_AUDIT.md`, `TESTPLAN.md`, toàn bộ `recon/*`, toàn bộ `download/*`.
→ Giữ nguyên working behavior và evidence gốc đúng yêu cầu brief rule 5.

---

## 3. Commands run & exit codes

| # | Command | Exit | Kết quả |
|---|---|---|---|
| 1 | `git branch --show-current && git rev-parse HEAD && git log --oneline -6 && git ls-files` | 0 | `main`, `2415a88f…`, 4 commit, 52 tracked files |
| 2 | `python --version` | 0 | 3.13.14 |
| 3 | `python -m pytest --version` | 1 | `No module named pytest` → **không cài**, dùng stdlib `unittest` |
| 4 | `python -c "...đọc 5 evidence JSON..."` | 0 | Kiểm chứng số liệu: 51/51, 19 probe, 11 API, 8 error case, 10 dot-probe |
| 5 | `python -c "...trích symbol bundle @offset..."` | 0 | Bản đồ client: `useSession @3175`, `locked @27900`, `POST …/unlock @24900`, `audioUrl @4257` |
| 6 | `git grep -IinE '<secret patterns>'` | 1* | 0 match (grep trả 1 khi không có match — expected) |
| 7 | `python -m unittest discover -s tests -v` (lần 1) | **1** | 4 FAIL: 3 do bash expand `$1b`/`$15`, 1 do assertion `.html/x` quá chặt |
| 8 | `python tests/make_fixtures.py` | 0 | 8 file, đã sửa lỗi `$` |
| 9 | `python -m unittest discover -s tests -v` (lần 2) | **1** | 1 FAIL: lệch 1 ký tự do RSC fixture thiếu newline cuối chunk |
| 10 | Sửa generator + `python -m unittest discover -s tests -v` (lần 3) | **0** | `Ran 37 tests … OK` |
| 11 | `python -m compileall -q <8 file .py>` | 0 | Không lỗi cú pháp |
| 12 | Determinism check: hash 8 fixture → regenerate → hash lại | 0 | `identical 8 files` |
| 13 | Secret scan trên tracked files (`csrf-token=`, `session-token=`, `Bearer`, `gh[pousr]_`, `TTM_COOKIE=`, `Cookie:`) | 0 matches | Clean |
| 14 | `git diff --cached --check` (trước `.gitattributes`) | **2** | 5 cảnh báo "trailing whitespace" do CRLF cố ý trong `free_chapter.rsc` |
| 15 | Thêm `.gitattributes` (`-text -whitespace`) → `git add --renormalize .` → `git diff --cached --check` | **0** | Sạch |
| 16 | `python -m unittest discover -s tests` sau renormalize | **0** | 37/37 OK — fixture không bị đổi byte |

**Lý do 2 lần test fail ban đầu (đã fix, ghi lại để không lặp):**
- Dùng `python -c "...$1b..."` trong bash → shell expand `$1` thành rỗng. Chuyển
  sang `tests/make_fixtures.py` (file, không inline).
- `.html/x` trả **404** (route không tồn tại) nhưng vẫn không bị gate → assertion
  "mọi case không gate phải 200" là sai; sửa thành 8×200 + 1×404.
- Chunk RSC thật kết thúc bằng newline; fixture thiếu → body lệch 1 ký tự.

---

## 4. Test results

```
Ran 37 tests in 0.079s
OK
```
- `TestRSCParser` 9/9 — flight stream, props, TOC, chunk newline, prefix, module-ref, UTF-8
- `TestInspectChannels` 5/5 — free/locked HTML, free/locked RSC, HTML=RSC cùng độ dài
- `TestClassificationRules` 7/7 — **status code không phải input của classifier**, redaction
- `TestCacheIsolationClassifier` 5/5 — không có A/B → `UNKNOWN`, `Vary` không chứng minh leak
- `TestEvidenceIntegrity` 11/11 — re-compute 51/51, 48 khoá, 19 probe, 11 API, 10 dot-probe, 8 error, 3× DYNAMIC, `sessions=null`

**Build/lint:** repo không có `package.json`, `pyproject.toml`, `requirements.txt`,
Makefile hay CI config → không có build/lint command chính thức. Thay bằng
`compileall` (exit 0). Không cài thêm dependency mới (dùng `unittest` stdlib;
`requests`/`bs4`/`lxml` đã có sẵn từ các script cũ, tests chỉ import chứ không gọi).

---

## 5. Runtime verification

> **"not verified at runtime"** cho Workstream 2, 3, 4 (phần staging), 5.

Không có request nào tới ứng dụng trong đợt audit này. Mọi kết luận runtime trong
`NEXT_AUDIT.md` / `FINDINGS.md` §13 đều **trích lại từ evidence anonymous đã capture
ngày 2026-11-14** (commit `2415a88`), không phải quan sát mới.

**Prerequisite còn thiếu, chính xác:**
1. Staging environment được ủy quyền (base URL), tách khỏi production.
2. `TTM_ALLOWED_STAGING_HOSTS` — **danh sách host staging, exact match**, phân cách
   bằng dấu phẩy. Bắt buộc kể từ D-1; host không có trong danh sách sẽ bị từ chối.
3. Hai tài khoản test độc lập A (có entitlement) / B (không có), cung cấp qua
   `TTM_COOKIE_A` / `TTM_COOKIE_B` — không commit giá trị.
4. Một **test chapter synthetic** (hoặc được phê duyệt rõ): `slug`, `chapterNumber`,
   `chapterId`. Không dùng chương thật.
5. Xác nhận scope cho phép mutate nếu chạy đủ Workstream 3
   (`POST /api/chapters/<id>/unlock`, `/api/reading-history`, comments) → đặt
   `TTM_MUTATE_AUTHORIZED=1` **và** truyền `--allow-mutate`. Thiếu một trong hai
   ⇒ harness từ chối mọi write (exit 3).

Thiếu (1)–(4) → `--sessions` vô nghĩa: nếu A vẫn `locked:true`, classifier trả
`UNKNOWN_A_NOT_ENTITLED` (đã có unit test).

---

## 6. Next verifiable step

```bash
# BƯỚC 0 — pre-flight, KHÔNG cần staging, KHÔNG cần cookie:
python -m unittest tests.test_staging_e2e_local -v   # exit 0, evidence ra thư mục tạm
# -> xác nhận đường chạy thật của harness còn nguyên trước khi dùng nó

# Sau khi có staging + 2 tài khoản + test chapter synthetic:
export TTM_STAGING_URL='https://staging.<domain-cua-ban>'
export TTM_ALLOWED_STAGING_HOSTS='staging.<domain-cua-ban>'   # exact match
export TTM_COOKIE_A='<session A>'   # KHÔNG commit
export TTM_COOKIE_B='<session B>'   # KHÔNG commit
export TTM_TEST_SLUG='...' TTM_TEST_CHAPTER='1' \
       TTM_TEST_CHAPTER_ID='...' TTM_TEST_STORY_ID='...'

python ttm_entitlement_audit.py --sessions
python ttm_staging_audit.py --run --out recon/staging_audit.json   # exit 0 / 3 / 4
python -m unittest discover -s tests -v

# Chỉ khi scope cho phep tao record synthetic:
export TTM_MUTATE_AUTHORIZED=1
python ttm_staging_audit.py --run --allow-mutate --out recon/staging_audit.json
```

Đọc `recon/entitlement_audit.json` → `sections.cache.sessions`:
- `A.locked == false && A.body_chars > 200` → phép thử hợp lệ.
- `B_received_A_content == true` → **mới** được kết luận leak (kèm `body_sha`).
- `false` + B `locked:true, body=0` → cách ly đúng.
- Kiểm tra `A_again` / `anon` để phát hiện staleness; lưu kèm fingerprint build.

Đọc `recon/staging_audit.json` → `sections.ws2_object_authz.objects`:
- `needs_review == true` (chỉ khi `a_has_session_specific_data` **và** `b_equals_a`)
  → có dấu hiệu cross-session; **chưa** phải kết luận IDOR — phải đối chiếu
  record mà A/B đã tạo.
- `UNKNOWN_NO_SESSION_SPECIFIC_DATA` → cả hai rỗng, chưa có gì để kết luận.

Đọc `recon/staging_audit.json` → `sections.ws2_object_authz.write_phase.records`:
- `OBSERVED_ISOLATED` → A đọc được, B không, anon bị từ chối, ghi của B không
  làm đổi record của A.
- `OBSERVED_NEEDS_REVIEW` → B đọc được record của A, **hoặc** ghi của B đã làm đổi
  record của A. Cần đối chiếu `a_record_sha256` vs `a_record_sha256_after_B_write`.
- `UNKNOWN_NO_SYNTHETIC_RECORD` → server không nhận POST (chưa có bản ghi) → chưa
  có gì để kết luận.

Đọc `recon/staging_audit.json` → `sections.ws4_audio_entitlement`:
- `audio_state` ∈ {`OBSERVED_CONSISTENT`, `OBSERVED_NEEDS_REVIEW`,
  `UNKNOWN_A_NO_AUDIO`, `UNKNOWN_A_NOT_ENTITLED`, `UNKNOWN_MISSING_SIGNAL`}.
- `UNKNOWN_A_NO_AUDIO` **không phải** kết luận thành công: A được entitlement
  nhưng không có audio ⇒ phép thử không có ý nghĩa, cần kiểm tra lại tài khoản.

**Exit code của `--run`:** `0` = chạy xong; `3` = prerequisite thiếu / write chưa
được ủy quyền; `4` = bị dừng do 403/429 (evidence đã flush với `aborted: true`).

Sau đó: Workstream 3 với **non-content test objects** do chính A/B tạo; Workstream 4
với cấu hình CDN thật (nếu chủ sở hữu cung cấp); Workstream 5 với synthetic audio
asset; và re-verify H1 trên build hiện tại.

---

## 7. Rủi ro / lưu ý cho người nhận

- Repo đang **public**, chứa 3 file `download/.../*.md` là **full-text chương miễn phí
  thật** của production (từ commit `2959fa1`). Không đọc/sửa/xoá trong đợt này theo
  brief rule 5. Chủ repo nên cân nhắc gỡ hoặc thay bằng synthetic fixture.
- Evidence `recon/*.html` cũng chứa HTML production thật (đã cắt 4 000 ký tự ở
  `recon/audit/`). Không có secret, nhưng là dữ liệu production.
- `NEXT_AUDIT.md` §2 dùng **byte offset** thay vì line number vì bundle client đã
  minify thành 1 dòng; đây không phải "exact source line" của server code.
- Mọi "code path" server là **Inferred**. Không bịa tên file/function server.
