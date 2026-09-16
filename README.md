# ReconHub — Burp Suite 진단 정보 정리 확장

## 개요

**ReconHub**는 모의진단 중 Burp에 쌓인 **Proxy History / Site Map**을 순회하여 진단에 필요한 정보를
자동으로 추출·정리하는 Burp Suite 확장(Montoya API, Java)입니다. 엔드포인트·파라미터 인벤토리화,
민감정보·미스컨피그 탐지, JavaScript 수집·분석, 기술 핑거프린팅을 수행하고 결과를 **JSON / HTML
리포트**와 재적재 가능한 **State 백업**으로 내보냅니다.

대상 서버에 직접 트래픽을 발생시키지 않는 **수동(passive) 분석**이 기본이며, 부하를 유발할 수 있는
기능은 두지 않습니다(모든 분석은 이미 캡처된 트래픽만 사용).

## 기능

**탭 구성**

| 탭 | 설명 |
|----|------|
| **Dashboard** | 카운트(요청·엔드포인트·파라미터·Findings·JS·호스트)와 심각도 요약을 **한 줄 컴팩트 스트립**(좁은 폭에서 자동 줄바꿈)으로, **호스트 스코어카드(좌: 호스트·엔드포인트·파라미터 목록 / 행 선택 시 우: 심각도별 칩·실제 누락 보안헤더 이름)**, **Top Findings(유형별 건수)**, **주목 엔드포인트(고위험 파라미터·admin/api 경로)**, Top hosts 차트, **파라미터 클래스 요약**. 각 표는 **우클릭으로 해당 항목을 다른 탭에서 필터링해 보기**(호스트→Endpoints/Parameters/Findings, 유형→Findings, 엔드포인트→Endpoints) 및 Copy·브라우저 열기 |
| **Endpoints** | method + 정규화 URL로 dedup한 엔드포인트 인벤토리(출처: proxy/sitemap/js/spec). 컬럼: Method·Host·Path·Status·Content-Type·Params·**Auth(auth/anon/both — 인증 없이 관찰된 2xx는 경고색)**·Source. 행 선택 시 하단에 원문 Request/Response, 우클릭 → Send to Repeater |
| **Parameters** | 엔드포인트별 파라미터(query/body/JSON/cookie). 컬럼: Host·Endpoint·Type·Name·Value·**Class(취약점 후보)**·Reflected·Seen. 기본 정렬 host→endpoint, 행 선택 시 매칭 Request/Response |
| **Findings** | 아래 *탐지 항목*을 심각도 순으로 집계. 컬럼: Severity·**Category(Secret/PII/Auth/Misconfig/Info leak/API/Injection/Comment)**·Type·Evidence·Location·Value·Seen·Status. **카테고리 필터(건수 표시) + 심각도 빠른 필터**, 행 선택 시 원문 + **JWT 디코드 탭**, 우클릭으로 **트리아지** 지정·Repeater/Intruder 전송·**해당 호스트의 Endpoints/Parameters로 이동**. TYPE·EVIDENCE는 짧게 식별 가능한 형태(상세는 툴팁·원문 뷰어). 노이즈는 **Settings → Findings display**(최소 심각도·카테고리 뮤트)로 제어 |
| **JS Assets** | 수집 JS를 SHA-256으로 dedup 저장(옵션: 디스크 저장), JS 내 엔드포인트·시크릿 추출. 행 선택 시 메타·저장파일 열기·관련 엔드포인트/Findings |
| **Tech** | 헤더/쿠키/JS 라이브러리 기반 호스트별 기술 식별 + 보안 헤더 누락 체크리스트 |
| **Settings** | 스코프·패시브 토글·커스텀 탐지 규칙·Ingest·각종 내보내기·State 백업 (아래 *사용법* 참고) |

**탐지 항목 (Findings)**

- **시크릿/키** — AWS·Google·GitHub·GitLab·Slack·Stripe·Twilio·SendGrid·npm·Shopify·Square·OpenAI·
  Postman·New Relic·Databricks·Telegram 등 API 키/토큰, JWT, private key, Bearer/Basic 인증 헤더,
  S3/GCS/Azure 스토리지 URL, 일반 `api_key=…` 할당식
- **PII** — 주민등록번호(날짜·체크섬 검증), 카드번호(Luhn+BIN 검증), 휴대전화, 이메일, 내부 IPv4
- **요청 기반 단서(passive)** — URL(query)에 실린 시크릿/토큰(이름 클래스·JWT·고엔트로피), redirect 파라미터가 `Location` 헤더에 반사되는 **오픈 리다이렉트 후보**, 응답 HTML에 인코딩 없이 반사되는 **파라미터(XSS 테스트 후보, INFO)**
- **응답 시그니처** — 스택트레이스·SQL 에러·디버그 모드·디렉터리 리스팅
- **미스컨피그** — CORS(와일드카드/반사 + credentials), 쿠키 HttpOnly/Secure/SameSite 누락, **CSP 약점**
  (`unsafe-inline`·`unsafe-eval`·와일드카드 소스·`frame-ancestors`/`object-src` 누락), **인증 응답 캐시 가능**
  (no-store/private 없는 인증 JSON), **혼합 콘텐츠**(https 페이지의 http 하위 리소스)
- **노출 파일** — 히스토리에 이미 잡힌 `.env`·`.git/`·`.htpasswd`·`wp-config`·`id_rsa`·`docker-compose` 등
  민감 파일과 `.bak`·`.old`·`.sql`·`.dump` 백업이 2xx로 서빙되는 경우
- **권한/인가 단서** — `role: admin`, `isAdmin: true`, `permissions/scopes/authorities`, `access_level` 등
- **API 표면** — OpenAPI/Swagger 스펙 노출(정의된 경로·파라미터를 인벤토리로 흡수), GraphQL introspection
- **주석** — HTML/JS 주석 중 흥미로운 키워드

> 시크릿·PII 등 민감값은 화면에선 전체 확인·복사가 가능하고, JSON/HTML 리포트에선 마스킹됩니다.

**모든 탭 공통**

- **Search 바** — 한/영 동시 검색, request/response 본문까지 검색, 정규식/대소문자/다중 AND·제외(`-단어`)/컬럼 지정
- **정렬** — 컬럼 헤더 클릭 시 오름차순 → 내림차순 → 기본(해제) 3단계 순환
- **CSV…** — 현재 화면(검색·정렬 반영)을 CSV로 저장
- 행 우클릭 — Copy cell/URL, Open in browser, Send to Repeater/Intruder, **Copy as curl**

## 사용법

**빌드** (Java 17+, Gradle wrapper 포함 — 별도 설치 불필요):

```bash
./gradlew shadowJar        # Windows: gradlew.bat shadowJar
```

산출물: `build/libs/reconhub-<version>-all.jar`

**설치**: Burp → **Extensions → Add** → Extension type **Java** → 위 JAR 선택 →
상단에 **ReconHub** 탭 생성 확인.

**기본 진단 흐름**

1. 진단 대상을 **Target → Scope**에 등록(기본 스코프 모드는 스코프 내 트래픽만 처리).
   필요 시 **Settings → Include/Exclude 정규식**으로 범위를 세밀 조정.
2. 이미 쌓인 트래픽은 **Settings → Ingest Site Map**으로 일괄 분석(진행 바·**Cancel** 지원).
   확장 로드 시 자동 분석하려면 **Auto-ingest site map on load** 토글.
3. 이후 브라우징하는 신규 트래픽은 **Capture new traffic live** 토글로 자동 반영.
4. 각 탭에서 확인(행 선택 시 하단 원문 Request/Response) → **Findings**는 우클릭으로 트리아지하며 정리.
5. 특정 요청만 취합하려면 Proxy 등 다른 탭에서 우클릭 → **Send to ReconHub**(스코프 무시).

**내보내기 / 백업** (Settings)

- **Export JSON / HTML / Markdown / SARIF** — 공유용 리포트. HTML은 상단에 **목차·행 검색·심각도 필터·섹션
  접기**와 심각도·카테고리 요약, **호스트별 위험 스코어카드**(엔드포인트·심각도별 건수·가중 점수)를 포함.
  **SARIF 2.1.0**은 CI/코드 스캐닝용(시크릿 원문 미포함, 안정적 fingerprint). HTML·Markdown·SARIF 모두
  **Confirmed only / Exclude false positives** 체크박스로 내보낼 범위를 트리아지 기준으로 좁힐 수 있음.
- **워드리스트(Paths / Param names / Hosts)** — ffuf·Intruder용 텍스트(정렬·중복 제거).
- **State Export / Import** — 수집 데이터 전체를 백업/복원(프로젝트 이동용). 원본 request/response 포함
  여부 선택 가능하며, Import 시 교체/병합 선택.

**커스터마이징**

- **커스텀 탐지 규칙** — Settings에서 이름·심각도·정규식으로 규칙을 추가/삭제. 내장 시크릿 스캔과 함께
  동작하고 Burp 재시작 후에도 유지되며, 신규 트래픽과 다음 Ingest부터 적용됩니다.
- **수집 JS 저장** — **Save collected JS to disk** 활성 시 **JS 저장 폴더**(기본 `~/reconhub/js`)에
  해시 dedup되어 저장됩니다.

## 변경 이력

버전은 [시맨틱 버저닝](https://semver.org/lang/ko/)(`MAJOR.MINOR.PATCH`)을 따른다.

### 0.24.0
- **Dashboard 표 정렬 3단계 순환**: 호스트 스코어카드·Top findings·주목 엔드포인트 표의 컬럼 헤더 클릭도 **오름차순 → 내림차순 → 기본(해제)** 3단계로 순환(기존 데이터 탭과 동일하게 통일).
- **CSV 버튼 위치 고정**: 각 탭 상단 툴바에서 **CSV…** 버튼을 **우측 끝으로 고정**(검색·필터는 좌측, 내보내기는 우측)해 위치를 일관되게 유지.
- **Settings 가시성 개선**: Settings 탭을 **스크롤 가능**하게 해 창이 작거나 절반 폭이어도 하단 섹션까지 모두 접근 가능. 섹션 헤더를 **악센트 색 + 구분선(전체 폭)**으로 강조해 스캔하기 쉽게 개선.

### 0.23.0
- **리포트 강화**: HTML/Markdown 리포트에 **호스트별 위험 스코어카드**(호스트별 엔드포인트·High/Medium/Low/Info 건수·가중 점수, 점수 내림차순) 추가. HTML은 목차에 Host risk 링크 포함.
- **SARIF 2.1.0 내보내기**: Settings에 **Export SARIF…** 추가 — CI/코드 스캐닝 수집용. 심각도→level(error/warning/note) 매핑, 규칙(유형)·위치(URL)·안정적 partialFingerprint 포함, **시크릿 원문은 미포함**(마스킹 값·해시 fingerprint). Confirmed only/Exclude FP 옵션 반영.

### 0.22.0
- **Findings 노이즈 제어**: **Settings → Findings display**에 **최소 심각도 임계값**과 **카테고리 뮤트** 추가 — 수집 데이터는 유지한 채 Findings 탭 표시만 필터. 카테고리 필터 콤보에 **카테고리별 건수**를 실시간 표시(그룹 개요 + 드릴다운).
- **Findings→관련 항목 이동**: finding 우클릭에 **해당 호스트의 Endpoints/Parameters 보기** 추가(탭 전환 + 자동 필터).

### 0.21.0
- **탐지 확장(passive)**: 시크릿 제공자 추가(GitLab·npm·Shopify·Square·OpenAI·Postman·New Relic·Databricks·Telegram, 고정밀 prefix 규칙). **노출 민감 파일**(`.env`/`.git`/`.htpasswd`/`wp-config`/`id_rsa`/`docker-compose` 2xx 서빙 → HIGH, `.bak`/`.old`/`.sql`/`.dump` 백업 → MEDIUM), **혼합 콘텐츠**(https 페이지의 http 하위 리소스 → LOW), **인증 응답 캐시 가능**(no-store/private 없는 인증 JSON → LOW) Findings 추가. 모두 이미 캡처된 트래픽만 사용.

### 0.20.0
- **Findings 카테고리 분류**: 각 finding을 **Secret/PII/Auth/Misconfig/Info leak/API/Injection/Comment** 카테고리로 자동 분류(`FindingTaxonomy`). Findings 탭에 **Category 컬럼(색상 구분)**과 **카테고리 필터(콤보, 심각도 필터와 동시 적용)** 추가, HTML/Markdown 리포트에도 Category 컬럼과 **카테고리 요약**을 반영.
- **TYPE·EVIDENCE 간결화**: 장황하던 유형/근거 문구를 짧고 식별하기 좋은 형태로 정리(예: "CORS: reflected origin with credentials"→`CORS reflected +creds`, evidence `ACAO reflects Origin +creds`; "Open redirect candidate (param in Location)"→`Open redirect (candidate)`). 전체 맥락은 툴팁·Request/Response 뷰어에서 확인.

### 0.19.3
- **Dashboard 상단 정리**: 심각도 칩(HIGH/MEDIUM/LOW/INFO)이 좁은 폭에서 두 줄로 쪼개지지 않고 **항상 한 줄**로 유지되도록 변경(안 맞으면 pills 아래로 통째로 이동), 상단 세로 여백을 줄여 **위로 당김**.

### 0.19.2
- **HTML 리포트 레이아웃 개선**: 콘텐츠를 **중앙정렬**(고정 최대폭 컬럼), **Top hosts·Status codes·Content types**를 하나의 접이식 **Distribution 섹션**으로 묶어 토글, 필터(검색+심각도)를 TOC와 분리해 **라벨 붙인 필터 그룹**으로 재배치(가시성·사용성 개선). TOC에 Charts 링크 추가.

### 0.19.1
- **HTML 리포트 표 렌더링 수정**: 표 헤더 sticky를 제거해 스크롤 시 **첫 행이 헤더에 가려 깨지던 문제** 해결, TOC로 섹션 이동 시 제목이 상단 툴바에 가리지 않도록 `scroll-margin` 적용(**토글 클릭 가능**), Findings 표를 **고정 컬럼 폭**으로 정렬하고 Type 등 텍스트가 글자 단위로 쪼개지지 않게(단어 단위 줄바꿈) 개선.

### 0.19.0
- **PII 탐지 항목 정리**: **사업자등록번호·법인등록번호**는 취약점이 아닌 식별번호라 Findings에서 제거(주민등록번호·카드번호·휴대전화는 유지).

### 0.18.0
- **HTML 리포트 업그레이드**: 상단 sticky **목차/네비**(섹션 점프), **행 검색창**, **심각도 체크박스 필터**(High/Medium/Low/Info), 섹션 **접기/펼치기**, Summary에 **심각도 요약** 추가(외부 라이브러리 없이 인라인 JS/CSS).
- **Markdown 리포트 추가**: 티켓·문서 붙여넣기용 `.md` 리포트(값은 HTML과 동일하게 마스킹).
- **리포트 범위 옵션**: Settings에서 **Confirmed only / Exclude false positives** 체크로 HTML·Markdown 내보낼 Findings를 트리아지 기준으로 필터.

### 0.17.0
- **엔드포인트 인증 관찰(접근제어 단서)**: 각 엔드포인트가 **Authorization/Cookie와 함께(auth) / 없이(anon) / 둘 다(both)** 관찰됐는지 기록해 Endpoints 탭 **Auth 컬럼**으로 표시. 인증 없이 2xx로 관찰된 엔드포인트는 경고색으로 강조되어(정렬 가능) 미인증 접근·IDOR 테스트 후보를 빠르게 식별. State 백업에 포함.
- **Copy as curl**: 모든 탭 행 우클릭에 추가 — 캡처된 요청을 `curl` 명령 문자열로 클립보드에 복사(헤더·본문 포함, 트래픽 발생 없음).

### 0.16.0
- **요청 기반 탐지 추가(passive)**: URL query에 노출된 시크릿/토큰(이름 클래스·JWT·고엔트로피) → `Sensitive data in URL query`(MEDIUM), redirect 계열 파라미터 값이 3xx `Location` 헤더에 반사 → `Open redirect candidate`(MEDIUM), 응답 HTML에 인코딩 없이 반사되는 파라미터 값 → `Reflected parameter (XSS candidate)`(INFO). 모두 dedup·응답당 상한으로 노이즈 제한, 이미 캡처된 요청/응답만 사용.
- **한국 PII 확장**: **사업자등록번호**(10자리 가중치 체크섬)·**법인등록번호**(13자리 체크섬)를 검증 후 탐지(전부 동일 숫자 등 자명 케이스 배제). 민감값이라 리포트에선 마스킹.

### 0.15.0
- **Dashboard 상단 1줄화**: 카운트 pill과 심각도 칩을 한 줄로 합쳐 상단 공간 확보(좁아지면 자동 줄바꿈).
- **호스트 스코어카드 상세 개선**: 좌측 표 폭을 줄이고 분할 비율을 조정해 우측 상세가 잘리지 않게, 우측 상세를 **심각도 색 칩(HIGH/MEDIUM/LOW/INFO)** + **실제 누락 보안헤더 이름 칩**으로 재구성(가독성 향상).
- **추가 액션(탭 연동)**: 스코어카드·Top findings·주목 엔드포인트 표에서 **우클릭 → 다른 탭에서 필터링해 보기**(호스트→Endpoints/Parameters/Findings, 유형→Findings, 엔드포인트→Endpoints) 및 Copy host/URL·브라우저 열기.

### 0.14.0
- **Dashboard 레이아웃 개선(좁은 폭 대응)**: 상단 카운트 카드를 컴팩트 pill로 축소하고 심각도 칩과 함께 폭이 좁아지면 자동 줄바꿈(패널이 절반 폭이어도 한눈에 식별) — 상단 공간 차지 대폭 감소.
- **호스트 스코어카드 master-detail 전환**: 표에는 **Host·Endpoints·Params**만 남기고, 행 선택 시 **우측 상세 패널**에 해당 호스트의 High·Medium·Low·Info·Missing headers를 심각도 색으로 표시. 새로고침 시 선택 호스트 유지.

### 0.13.1
- **Dashboard 가시성 개선**: 호스트 스코어카드의 `H/M/L/I` 약어를 **High/Medium/Low/Info**로 풀고 심각도 색상+굵게로 강조. 잘리던 **Top hosts 차트** 높이 확보(중복 제목 제거). 섹션 제목 볼드·확대(15pt), 표 행 높이·헤더 강조, 전체 패딩/간격 확대 및 레이아웃 재배치(스코어카드 상단 전체폭 → Top findings·주목 엔드포인트 → Top hosts·파라미터 클래스).

### 0.13.0
- **Dashboard 재구성**: 가독성이 떨어지던 디렉터리 트리를 제거하고, 진단 우선순위 판단에 유용한 집계 뷰로 교체 — **호스트 스코어카드**(호스트별 엔드포인트·파라미터·Findings H/M/L/I·누락 보안헤더), **Top Findings**(유형별 건수 랭킹), **주목 엔드포인트**(고위험 파라미터 클래스 보유 또는 admin/api/graphql 경로), **파라미터 클래스 요약**(칩). Top hosts 차트는 유지.

### 0.12.0
- **Dashboard 개편**: 식별에 불필요한 상태코드·콘텐츠타입 막대 차트 제거, 대신 **수집 엔드포인트를 host→경로 디렉터리 트리(접이식)**로 표시(리프에 method·상태코드). Top hosts 차트는 유지.
- **Parameters 컬럼 순서 변경**: Host · Endpoint · Type · Name · **Value**(기존 Example) · Class · Reflected · Seen.
- **Findings 컬럼 순서 변경**: Severity · Type · **Evidence · Location · Value** · Seen · Status.
- 참고: JS에서 발견한 엔드포인트는 URL 문자열에 method 정보가 없어 method를 `JS`로 표기(추론하지 않음).

### 0.11.1
- **Parameters Host 컬럼·정렬**: Parameters 탭 맨 앞에 **Host 컬럼** 추가, 기본 표시 순서를 **host → endpoint**로 변경(같은 호스트끼리 모여 보임). JSON/HTML 리포트에도 host 반영.
- **카드번호 오탐 개선**: "Payment card number" 탐지를 **Luhn + 카드 브랜드(BIN) 범위 + 길이 화이트리스트 + 자명한 비-카드(전부 동일/연속 숫자) 배제**로 강화. Luhn만 우연히 통과하는 무작위 숫자열이 걸러짐(정상 BIN의 실제 카드만 탐지).

### 0.11.0
- **커스텀 탐지 규칙 UI**: Settings에서 사용자 정규식 규칙(이름·심각도·정규식)을 추가/삭제. 내장 시크릿 스캔과 함께 동작하며 신규 트래픽·다음 Ingest부터 적용. **Burp 재시작 후에도 유지**(Montoya 환경설정에 저장).
- **Ingest 진행률/취소**: Site Map 스윕 시 진행 바(done/total)와 **Cancel** 버튼 표시.
- **Findings 심각도 빠른 필터**: 상단 HIGH/MEDIUM/LOW/INFO 토글로 즉시 필터(미선택 = 전체).

### 0.10.0
- **Findings 트리아지**: 행 우클릭으로 **New/Reviewed/Confirmed/False positive** 상태 지정. Status 컬럼 추가, Confirmed는 굵게·False positive는 흐리게 강조. 상태는 State 백업 및 JSON/HTML 리포트에 포함.
- **워드리스트 내보내기**: Settings에서 수집한 **경로/파라미터명/호스트**를 각각 텍스트 파일로 내보내기(ffuf·Intruder용, 정렬·중복 제거).
- **표 CSV 내보내기**: 모든 탭 상단에 **CSV…** 버튼 추가 — 현재 화면(검색·정렬 반영)을 CSV로 저장.

### 0.9.0
- **PII 탐지(한국 특화)**: 응답에서 **주민등록번호**(날짜·체크섬 검증), **카드번호**(Luhn 검증), **휴대전화**를 Findings에 추가(민감값이라 리포트에선 마스킹). 검증을 거쳐 오탐 최소화. `Run passive checks` 토글에 포함.
- **JWT 디코드 뷰**: Findings 행 선택 시 상세의 **JWT 탭**에서 헤더·페이로드(pretty JSON)·주요 클레임(iss/sub/exp 등, 시간 사람이 읽게)·경고(`alg:none`, 만료, 장기 토큰)를 표시(서명 검증 없이 디코드만).
- **CSP 약점 분석**: `Content-Security-Policy`의 `unsafe-inline`/`unsafe-eval`, 와일드카드 소스, `frame-ancestors`/`object-src` 누락을 Findings로 보고.

### 0.8.0
- **API 스펙·GraphQL 인식(passive)**: 히스토리에 이미 잡힌 **OpenAPI/Swagger JSON**을 파싱해 정의된 경로·메서드를 엔드포인트(출처 `spec`)로, query/header/cookie 파라미터를 Parameters 탭으로 흡수. 문서에만 있고 실제로 눌러보지 않은 경로 발견에 유용. **GraphQL** 엔드포인트 관찰 시 표시하고, 응답에 `__schema`가 노출되면(introspection 활성) MEDIUM Findings로 보고. 캡처된 응답만 사용(추가 요청 없음).

### 0.7.0
- **파라미터 취약점 후보 자동 분류**: 파라미터 이름을 규칙(`patterns/param-classes.json`) 기반으로 IDOR·Redirect/SSRF·File/Path·SQLi/Sort·Command·Secret/Token·Debug 후보로 태깅. Parameters 탭에 **Class 컬럼**(강조·툴팁) 추가, 검색·JSON·HTML 리포트에도 반영. 완전 passive(캡처된 이름만 분류, 추가 요청 없음).

### 0.6.2
- **Findings 값 전체 표시·복사**: Value 컬럼을 마스킹 없이 **원본 값 전체**로 표시하고, 셀이 좁아 잘리면 마우스오버 툴팁으로 전체 값을 확인. 우클릭 **Copy cell**로 값 전체 복사 가능(Location/Evidence도 툴팁 제공). ※ JSON/HTML 리포트 export의 값은 기존대로 마스킹 유지.

### 0.6.1
- **HTML 리포트 표 깨짐 수정**: 긴 URL·시크릿·경로 값이 셀 안에서 줄바꿈되도록 처리(`overflow-wrap`/`word-break`)해, 칸이 눌려 글자가 겹쳐 보이던 문제 해결. 본문 폭도 소폭 확대.
- **정렬 3단계 순환**: 모든 탭에서 컬럼 헤더 클릭 시 **오름차순 → 내림차순 → 기본(정렬 해제)** 순으로 순환.

### 0.6.0
- **Site Map 탭 제거**: 트리 UI 가독성이 Burp 기본 사이트맵에 못 미쳐 기능을 롤백. 엔드포인트 열람은 **Endpoints** 탭(+행 선택 시 원문 Request/Response)으로 대체. 0.5.x에서 추가·조정하던 Site Map 관련 변경 일체 제거.

### 0.5.0
- **Findings 상세**: 행 선택 시 하단에 필드 요약 + 원본 Request/Response 뷰어(시크릿이 어디서 나왔는지 확인), 우클릭 Repeater/Intruder 전송. 백업(State)에도 finding 원문 포함.
- **JS Assets 상세**: URL·해시·크기·저장경로 + 저장 파일 열기 + 해당 JS에서 나온 엔드포인트/Findings 목록.
- **Tech 가시성 개선**: 선택 호스트의 기술·누락 보안헤더를 칩 목록으로 세로 표시(콤마 나열 해소).
- **강조 처리**: Findings 심각도 색상, Parameters 반사값 강조, Tech 누락 헤더 경고색.

### 0.4.0
- **권한(Authorization) 값 탐지 추가**: 응답·JS·JSON에서 `role: admin`, `isAdmin: true`, `permissions/scopes/authorities`, `access_level` 등 권한/역할 관련 값을 Findings에 별도 표시(`Run passive checks` 토글). 인가 테스트 단서용.

### 0.3.0
- **탐지 강화**: 흥미로운 응답(스택트레이스·SQL 에러·디버그·디렉터리 리스팅) 시그니처, 보안 미스컨피그(CORS 와일드카드/반사 + credentials, 쿠키 HttpOnly/Secure/SameSite 누락), HTML/JS 주석 추출을 Findings에 추가. `Analysis → Run passive checks` 토글.
- **행 우클릭 메뉴**(모든 탭): Copy cell / Copy URL / Open in browser / Send to Repeater / Send to Intruder.
- **Send to ReconHub**: Proxy 등 다른 Burp 탭에서 선택 요청을 우클릭으로 취합(스코프 무시).
- **뷰어 검색어 하이라이트**: Search 입력이 하단 Request/Response 뷰어에서 강조.
- **커스텀 스코프 정규식**(include/exclude), **정적 자산 제외 토글**(img/css/font/media, JS 제외), **로드 시 자동 Ingest** 추가.

### 0.2.0
- **상태(State) Export/Import 추가**: 수집한 전체 데이터(엔드포인트·파라미터·Findings·JS·기술·카운터)를 재적재 가능한 JSON 백업 파일로 저장/복원. 프로젝트 이동·백업 용도.
  - 옵션 **원본 request/response 포함**(기본 on): 포함 시 임포트 후에도 뷰어·본문 검색 동작(파일 커짐), 해제 시 분석 데이터만 저장.
  - Import 시 **교체(replace)/병합(merge)** 선택. 병합은 dedup 키로 중복 처리.
  - 리포트용 `Export JSON/HTML`과 별개 기능(상태 파일 형식: `reconhub-state`).

### 0.1.1
- **본문 한글 검색 수정**: 검색용 본문을 Content-Type charset(기본 UTF-8, EUC-KR 등 지원)으로 디코딩하도록 변경. 기존에는 바이트 매핑으로 한글이 깨져 영어만 검색되던 문제 해결.

### 0.1.0
- 각 탭의 **Filter를 Search로 개편**: 한국어·영어 동시 검색, request/response **본문 값까지 검색**.
- 검색 옵션 추가: 정규식(Regex) 토글, 대소문자 구분(Aa) 토글, 다중 키워드 AND + 제외(`-단어`), 필드(컬럼) 지정 검색.
- Endpoints/Parameters **Request/Response 뷰어 기본 세로 크기 확대** + 분할선 드래그로 조절.

### 0.0.0
- 최초 릴리스.
- Proxy History / Site Map 일괄 순회 + 신규 트래픽 라이브 캡처(스코프 필터링).
- 엔드포인트·파라미터 인벤토리(dedup), 시크릿/민감정보 탐지, JS 수집·분석, 기술 핑거프린팅.
- Endpoints/Parameters 행 선택 시 하단 Request/Response 뷰어, Send to Repeater.
- Dashboard 막대 차트 및 심각도 요약.
- JSON / HTML 리포트 내보내기.
