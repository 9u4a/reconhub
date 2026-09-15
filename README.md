# ReconHub — Burp Suite 진단 정보 정리 확장

## 개요

모의진단 중 Burp에 쌓인 **Proxy History / Site Map**을 순회하여 진단에 필요한 정보를 자동으로
추출·정리하고, JavaScript 파일을 수집·분석하며, 결과를 **JSON / HTML 리포트**로 내보내는
Burp Suite 확장(Montoya API, Java)입니다. 대상 서버에 직접 트래픽을 발생시키지 않는 **수동 분석**
방식입니다.

## 기능

| 탭 | 설명 |
|----|------|
| **Dashboard** | 요청·엔드포인트·파라미터·Findings·JS·호스트 카운트, 심각도별 요약, 상위 호스트/상태코드/콘텐츠타입 막대 차트 |
| **Endpoints** | method + 정규화 URL로 dedup한 엔드포인트 인벤토리(출처: proxy/sitemap/js/**spec**). 행 선택 시 하단에 Request/Response 표시, 우클릭 → **Send to Repeater** |
| **Parameters** | 엔드포인트별 파라미터(query/body/JSON/cookie) — **호스트**·경로·유형·**취약점 후보 클래스(IDOR·Redirect/SSRF·File/Path·SQLi·Command·Secret/Token·Debug)**·예시값·반사 여부·Seen. 기본 정렬 host→endpoint. 행 선택 시 매칭 Request/Response 표시 |
| **Findings** | 시크릿/민감정보(AWS·Google·GitHub·Slack 키, JWT, private key, S3, 이메일, 내부 IP) + **PII(주민등록번호·카드번호(Luhn)·휴대전화)** + 흥미로운 응답(스택트레이스·SQL 에러·디버그·디렉터리 리스팅) + 보안 미스컨피그(CORS·쿠키 플래그·**CSP 약점**) + 권한 값(role/admin/permissions 등) + **API 스펙 노출(OpenAPI/Swagger)·GraphQL introspection** + HTML/JS 주석, 심각도 정렬·**심각도 빠른 필터**. 행 선택 시 **JWT 디코드 탭**(헤더·클레임·만료·alg 경고), 우클릭으로 **트리아지 상태(New/Reviewed/Confirmed/False positive)** 지정·Repeater/Intruder 전송 |
| **JS Assets** | 수집한 JS를 SHA-256 해시로 dedup 저장, JS 내 엔드포인트·시크릿 추출. 출처 JS 파일 기록 |
| **Tech** | 헤더/쿠키/JS 라이브러리 기반 호스트별 기술 식별 + 보안 헤더 누락 체크리스트 |
| **Settings** | 스코프 모드/정규식, 패시브 검사·정적자산 제외·자동 Ingest 토글, JS 저장 폴더, 라이브 캡처/시크릿 스캔, **커스텀 탐지 규칙(정규식 추가·삭제, 재시작 후 유지)**, Ingest Site Map(**진행률·취소**), Clear, Export JSON/HTML, **워드리스트 내보내기(Paths/Param names/Hosts)**, State Export/Import(백업·복원) |

## 사용법

**빌드** (Java 17+, Gradle wrapper 포함 — 별도 설치 불필요):

```bash
./gradlew shadowJar        # Windows: gradlew.bat shadowJar
```

산출물: `build/libs/reconhub-<version>-all.jar`

**설치**: Burp → **Extensions → Add** → Extension type **Java** → 위 JAR 선택 →
상단에 **ReconHub** 탭 생성 확인.

**진단 흐름**:

1. 진단 대상을 **Target → Scope**에 등록(기본 스코프 모드는 스코프 내 트래픽만 처리).
2. 이미 쌓인 트래픽은 **Settings → Ingest Site Map**으로 일괄 분석.
3. 이후 브라우징하는 신규 트래픽은 **Capture new traffic live** 토글로 자동 반영.
4. 각 탭에서 확인(행 선택 시 하단에서 원문 Request/Response 확인) 후 **Export JSON / HTML**로 리포트 저장.
5. 수집한 JS는 **Settings → JS 저장 폴더**(기본 `~/reconhub/js`)에 해시 dedup되어 저장.

## 변경 이력

버전은 [시맨틱 버저닝](https://semver.org/lang/ko/)(`MAJOR.MINOR.PATCH`)을 따른다.

### 1.11.1
- **Parameters Host 컬럼·정렬**: Parameters 탭 맨 앞에 **Host 컬럼** 추가, 기본 표시 순서를 **host → endpoint**로 변경(같은 호스트끼리 모여 보임). JSON/HTML 리포트에도 host 반영.
- **카드번호 오탐 개선**: "Payment card number" 탐지를 **Luhn + 카드 브랜드(BIN) 범위 + 길이 화이트리스트 + 자명한 비-카드(전부 동일/연속 숫자) 배제**로 강화. Luhn만 우연히 통과하는 무작위 숫자열이 걸러짐(정상 BIN의 실제 카드만 탐지).

### 1.11.0
- **커스텀 탐지 규칙 UI**: Settings에서 사용자 정규식 규칙(이름·심각도·정규식)을 추가/삭제. 내장 시크릿 스캔과 함께 동작하며 신규 트래픽·다음 Ingest부터 적용. **Burp 재시작 후에도 유지**(Montoya 환경설정에 저장).
- **Ingest 진행률/취소**: Site Map 스윕 시 진행 바(done/total)와 **Cancel** 버튼 표시.
- **Findings 심각도 빠른 필터**: 상단 HIGH/MEDIUM/LOW/INFO 토글로 즉시 필터(미선택 = 전체).

### 1.10.0
- **Findings 트리아지**: 행 우클릭으로 **New/Reviewed/Confirmed/False positive** 상태 지정. Status 컬럼 추가, Confirmed는 굵게·False positive는 흐리게 강조. 상태는 State 백업 및 JSON/HTML 리포트에 포함.
- **워드리스트 내보내기**: Settings에서 수집한 **경로/파라미터명/호스트**를 각각 텍스트 파일로 내보내기(ffuf·Intruder용, 정렬·중복 제거).
- **표 CSV 내보내기**: 모든 탭 상단에 **CSV…** 버튼 추가 — 현재 화면(검색·정렬 반영)을 CSV로 저장.

### 1.9.0
- **PII 탐지(한국 특화)**: 응답에서 **주민등록번호**(날짜·체크섬 검증), **카드번호**(Luhn 검증), **휴대전화**를 Findings에 추가(민감값이라 리포트에선 마스킹). 검증을 거쳐 오탐 최소화. `Run passive checks` 토글에 포함.
- **JWT 디코드 뷰**: Findings 행 선택 시 상세의 **JWT 탭**에서 헤더·페이로드(pretty JSON)·주요 클레임(iss/sub/exp 등, 시간 사람이 읽게)·경고(`alg:none`, 만료, 장기 토큰)를 표시(서명 검증 없이 디코드만).
- **CSP 약점 분석**: `Content-Security-Policy`의 `unsafe-inline`/`unsafe-eval`, 와일드카드 소스, `frame-ancestors`/`object-src` 누락을 Findings로 보고.

### 1.8.0
- **API 스펙·GraphQL 인식(passive)**: 히스토리에 이미 잡힌 **OpenAPI/Swagger JSON**을 파싱해 정의된 경로·메서드를 엔드포인트(출처 `spec`)로, query/header/cookie 파라미터를 Parameters 탭으로 흡수. 문서에만 있고 실제로 눌러보지 않은 경로 발견에 유용. **GraphQL** 엔드포인트 관찰 시 표시하고, 응답에 `__schema`가 노출되면(introspection 활성) MEDIUM Findings로 보고. 캡처된 응답만 사용(추가 요청 없음).

### 1.7.0
- **파라미터 취약점 후보 자동 분류**: 파라미터 이름을 규칙(`patterns/param-classes.json`) 기반으로 IDOR·Redirect/SSRF·File/Path·SQLi/Sort·Command·Secret/Token·Debug 후보로 태깅. Parameters 탭에 **Class 컬럼**(강조·툴팁) 추가, 검색·JSON·HTML 리포트에도 반영. 완전 passive(캡처된 이름만 분류, 추가 요청 없음).

### 1.6.2
- **Findings 값 전체 표시·복사**: Value 컬럼을 마스킹 없이 **원본 값 전체**로 표시하고, 셀이 좁아 잘리면 마우스오버 툴팁으로 전체 값을 확인. 우클릭 **Copy cell**로 값 전체 복사 가능(Location/Evidence도 툴팁 제공). ※ JSON/HTML 리포트 export의 값은 기존대로 마스킹 유지.

### 1.6.1
- **HTML 리포트 표 깨짐 수정**: 긴 URL·시크릿·경로 값이 셀 안에서 줄바꿈되도록 처리(`overflow-wrap`/`word-break`)해, 칸이 눌려 글자가 겹쳐 보이던 문제 해결. 본문 폭도 소폭 확대.
- **정렬 3단계 순환**: 모든 탭에서 컬럼 헤더 클릭 시 **오름차순 → 내림차순 → 기본(정렬 해제)** 순으로 순환.

### 1.6.0
- **Site Map 탭 제거**: 트리 UI 가독성이 Burp 기본 사이트맵에 못 미쳐 기능을 롤백. 엔드포인트 열람은 **Endpoints** 탭(+행 선택 시 원문 Request/Response)으로 대체. 1.5.x에서 추가·조정하던 Site Map 관련 변경 일체 제거.

### 1.5.0
- **Findings 상세**: 행 선택 시 하단에 필드 요약 + 원본 Request/Response 뷰어(시크릿이 어디서 나왔는지 확인), 우클릭 Repeater/Intruder 전송. 백업(State)에도 finding 원문 포함.
- **JS Assets 상세**: URL·해시·크기·저장경로 + 저장 파일 열기 + 해당 JS에서 나온 엔드포인트/Findings 목록.
- **Tech 가시성 개선**: 선택 호스트의 기술·누락 보안헤더를 칩 목록으로 세로 표시(콤마 나열 해소).
- **강조 처리**: Findings 심각도 색상, Parameters 반사값 강조, Tech 누락 헤더 경고색.

### 1.4.0
- **권한(Authorization) 값 탐지 추가**: 응답·JS·JSON에서 `role: admin`, `isAdmin: true`, `permissions/scopes/authorities`, `access_level` 등 권한/역할 관련 값을 Findings에 별도 표시(`Run passive checks` 토글). 인가 테스트 단서용.

### 1.3.0
- **탐지 강화**: 흥미로운 응답(스택트레이스·SQL 에러·디버그·디렉터리 리스팅) 시그니처, 보안 미스컨피그(CORS 와일드카드/반사 + credentials, 쿠키 HttpOnly/Secure/SameSite 누락), HTML/JS 주석 추출을 Findings에 추가. `Analysis → Run passive checks` 토글.
- **행 우클릭 메뉴**(모든 탭): Copy cell / Copy URL / Open in browser / Send to Repeater / Send to Intruder.
- **Send to ReconHub**: Proxy 등 다른 Burp 탭에서 선택 요청을 우클릭으로 취합(스코프 무시).
- **뷰어 검색어 하이라이트**: Search 입력이 하단 Request/Response 뷰어에서 강조.
- **커스텀 스코프 정규식**(include/exclude), **정적 자산 제외 토글**(img/css/font/media, JS 제외), **로드 시 자동 Ingest** 추가.

### 1.2.0
- **상태(State) Export/Import 추가**: 수집한 전체 데이터(엔드포인트·파라미터·Findings·JS·기술·카운터)를 재적재 가능한 JSON 백업 파일로 저장/복원. 프로젝트 이동·백업 용도.
  - 옵션 **원본 request/response 포함**(기본 on): 포함 시 임포트 후에도 뷰어·본문 검색 동작(파일 커짐), 해제 시 분석 데이터만 저장.
  - Import 시 **교체(replace)/병합(merge)** 선택. 병합은 dedup 키로 중복 처리.
  - 리포트용 `Export JSON/HTML`과 별개 기능(상태 파일 형식: `reconhub-state`).

### 1.1.1
- **본문 한글 검색 수정**: 검색용 본문을 Content-Type charset(기본 UTF-8, EUC-KR 등 지원)으로 디코딩하도록 변경. 기존에는 바이트 매핑으로 한글이 깨져 영어만 검색되던 문제 해결.

### 1.1.0
- 각 탭의 **Filter를 Search로 개편**: 한국어·영어 동시 검색, request/response **본문 값까지 검색**.
- 검색 옵션 추가: 정규식(Regex) 토글, 대소문자 구분(Aa) 토글, 다중 키워드 AND + 제외(`-단어`), 필드(컬럼) 지정 검색.
- Endpoints/Parameters **Request/Response 뷰어 기본 세로 크기 확대** + 분할선 드래그로 조절.

### 1.0.0
- 최초 릴리스.
- Proxy History / Site Map 일괄 순회 + 신규 트래픽 라이브 캡처(스코프 필터링).
- 엔드포인트·파라미터 인벤토리(dedup), 시크릿/민감정보 탐지, JS 수집·분석, 기술 핑거프린팅.
- Endpoints/Parameters 행 선택 시 하단 Request/Response 뷰어, Send to Repeater.
- Dashboard 막대 차트 및 심각도 요약.
- JSON / HTML 리포트 내보내기.
