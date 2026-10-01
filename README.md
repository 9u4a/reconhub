# ReconHub — Burp Suite 진단 정보 정리 확장

## 개요

**ReconHub**는 Burp의 **Proxy History / Site Map**을 순회해 엔드포인트·파라미터 인벤토리, 민감정보·
미스컨피그 탐지, JS 수집·분석, 기술 핑거프린팅을 수행하고 **JSON/HTML/Markdown/SARIF 리포트**와
재적재 가능한 **State 백업**으로 내보내는 확장(Montoya API, Java)입니다. 기본은 캡처된 트래픽만 쓰는
**수동(passive) 분석**이며, **Bruteforce**와 **Match & Replace** 두 탭만 ACTIVE(대상에 요청 전송)입니다
— Bruteforce는 실행마다 확인 다이얼로그가 유일한 게이트, Match & Replace는 **Settings에서 기본 꺼짐
상태를 먼저 켜야** 하고 그 위에 확인 다이얼로그도 매번 필요합니다.

## 기능

| 탭 | 한 줄 설명 |
|----|------|
| **Dashboard** | 요약 통계 + 호스트 스코어카드, 다른 탭으로 크로스탭 이동, **호스트 데이터 삭제(다중 선택)** |
| **Endpoints** | 엔드포인트 인벤토리 (dedup, Auth 관찰), **다중 선택 → Match & Replace 전송** |
| **Parameters** | 파라미터 + 취약점 후보 Class 자동 분류, **다중 선택 → Match & Replace 전송** |
| **Findings** | 탐지 결과 심각도/카테고리 집계 + 트리아지, **다중 선택 → Match & Replace 전송** |
| **JS Assets** | JS 파일 수집·분석 (엔드포인트/시크릿 추출), **다중 선택 → Match & Replace 전송** |
| **Tech** | 호스트별 기술 식별 + 보안 헤더 체크 |
| **Bruteforce** ⚠**ACTIVE** | 알려진 경로(관리자·API·노출 파일 등) 탐색 |
| **Match & Replace** ⚠**ACTIVE** | Endpoints/Parameters/Findings/JS Assets에서 선택한 행에 헤더/쿠키 값 또는 원문 전체 치환 규칙(**여러 개 체이닝 가능**) 적용해 재전송, 결과+상세 확인 |
| **Snapshot Diff** | 저장해둔 State 파일을 불러와 현재 데이터와 비교, 새로 생긴/사라진 항목 표시 |
| **Settings** | 스코프·규칙·Ingest·내보내기(**북마크만** 옵션 포함)·State 백업, **스코프 밖 호스트 일괄 삭제**, Match & Replace 켜기/스로틀 |

**탐지 항목**: 시크릿(API 키/JWT/쿠키값 포함)·PII·오픈 리다이렉트·반사 XSS 후보·응답 시그니처(스택
트레이스/SQL 에러)·CORS/쿠키/CSP/캐시 미스컨피그·노출 파일(`.env`·`.git`)·OpenAPI/Swagger·GraphQL
introspection·소스맵 노출·주석·누락 보안 헤더.

**공통 기능**: 검색(정규식·AND·본문)·정렬(**`Shift`+클릭으로 다중 컬럼**)·CSV 내보내기·행 우클릭 Copy/Repeater/Intruder/
curl·JS Beautify·**북마크/메모**·**키보드 단축키**·**다크테마 자동 대응**·**모든 표 줄무늬(zebra)
배경**. Endpoints·Parameters는 **체크박스 다중값 필터**(Burp History 필터처럼)도 제공, Findings·Tech는
**Host 체크박스 필터**도 제공. 자세한 내용은 아래 [기능 상세](#기능-상세) 참고.

## 사용법

**빌드** (Java 17+, Gradle wrapper 포함):

```bash
./gradlew shadowJar        # Windows: gradlew.bat shadowJar
```

산출물 `build/libs/reconhub-<version>-all.jar`을 Burp **Extensions → Add → Java**로 로드
(각 [Releases](https://github.com/9u4a/reconhub/releases)에서 빌드된 JAR 직접 다운로드도 가능).

**기본 흐름**: Target → Scope 등록 → **Settings → Ingest Site Map**(또는 Auto-ingest·Live capture)로
분석 → 각 탭에서 확인(행 선택 시 하단 원문 Request/Response) → **Findings** 우클릭으로 트리아지 →
Settings에서 **JSON/HTML/Markdown/SARIF** 리포트·워드리스트·**State Export/Import** 내보내기.
특정 요청만 취합하려면 다른 Burp 탭에서 우클릭 **Send to ReconHub**.

## 기능 상세

### Dashboard
카운트·심각도 요약, **호스트 스코어카드**(선택 시 심각도별·누락 보안헤더 상세), Top findings·주목
엔드포인트·파라미터 클래스. 우클릭으로 다른 탭에서 필터링해 보기. 호스트 우클릭 **Delete all data for
this host…**로 그 호스트의 엔드포인트/파라미터/파인딩/JS/Tech 데이터를 전부 삭제(삭제 전 건수 미리보기,
확인 필수, Burp 자체 Proxy History/Site Map은 건드리지 않음) — **Ctrl/Shift로 여러 호스트 다중 선택 후
한 번에 삭제**도 가능. Endpoints/Parameters/Findings/Tech 탭에서도 동일(단일 호스트) 삭제 메뉴 제공.

### Endpoints
method+정규화 URL로 dedup한 인벤토리(인증 관찰 Auth 컬럼 포함), 행 선택 시 원문 Request/Response.
**XML/SOAP** Content-Type이면 우클릭 **View payload cheatsheet (XXE)…** 제공. 검색창 옆 **Method/
Status/Type 필터 버튼**으로 값을 체크박스로 골라 필터링(Burp History 필터처럼, 여러 개 동시 선택 가능).

### Parameters
엔드포인트별 파라미터(query/body/JSON/cookie) + 취약점 후보 **Class** 자동 분류(IDOR·Redirect/SSRF·
File/Path·SQLi/Sort·Command·**SSTI**). 우클릭 **Payload cheatsheet ▸**로 자동 제안 클래스는 원클릭,
**전체 클래스도 항상 수동으로 직접 선택 가능**(Basic/Bypass·우회 페이로드, Intruder에 클래스당 2세트
등록). **JSON 파라미터**는 Prototype Pollution, **직렬화 값처럼 보이는 파라미터**(Java/PHP
serialize·ViewState)는 Deserialization이 이름과 무관하게 자동 제안. **Location/Class 필터 버튼**으로
체크박스 다중값 필터링.

### Findings
시크릿·PII·미스컨피그 등을 심각도·**카테고리**로 집계(필터·트리아지·JWT 디코드, 행 선택 시 원문).
우클릭 **Payload cheatsheet ▸**로 반사 XSS·오픈 리다이렉트는 자동 제안, **전체 클래스도 수동 선택
가능**. 검색창 옆 **Host 필터 버튼**으로 여러 호스트를 체크박스로 골라 필터링(심각도/카테고리 필터와
동시 적용).

### JS Assets
JS 수집(SHA-256 dedup·옵션 저장) + 내부 엔드포인트·시크릿 추출. 해시 이름 코드-스플릿 청크를 열어보지
않고 구분할 수 있는 **Preview** 컬럼(감지된 엔드포인트 샘플, 없으면 코드 스니펫), 행 선택 시
**Response 탭**에서 캡처된 응답 원문 확인(임포트된 파일은 없음). 트래픽에 안 잡힌 파일은 **Import JS
file(s)…**로 로컬에서 불러와 동일 분석.

### Tech
호스트별 기술 식별 + 보안 헤더 누락 체크(Findings에도 동일 항목이 LOW로 집계). 검색창 옆 **Host 필터
버튼**으로 여러 호스트를 체크박스로 골라 필터링.

### Bruteforce ⚠ACTIVE
알려진 경로(관리자 패널·API 문서·노출 파일·CI/CD·IDE 아티팩트 등, 내장 워드리스트 약 380개) 탐색.
**Hits 탭**에서 확인된 hit을 바로 표로 확인(호스트·경로·상태·길이·태그, 우클릭 Copy/Open in
browser). 스로틀(지연·동시성·호스트당 상한) 조절, **Activity log**에 보낸 경로·응답(상태·길이·
유사도)을 실시간 기록. Dashboard/Endpoints/Parameters/Tech/Findings에서 호스트 우클릭 → **확인
다이얼로그에서 대상 주소(스킴·포트 포함) 직접 수정 + 매 실행마다 확인**(이게 유일한 게이트) — 기본
스킴은 그 호스트에서 **이미 관찰된 트래픽**을 참고해 자동 선택(http만 관찰된 호스트에 https를 강제해
전부 실패하는 상황 방지). Soft-404 판정은 **본문 유사도 기반**(경로가 그대로 echo되는 404 페이지에도
오탐 없음). 결과는 Endpoints(Source=bruteforce)·Findings 탭에도 반영, Jobs/Hits는 **State
Export/Import에도 완료 기록으로 보존**.

### Match & Replace ⚠ACTIVE
**Endpoints/Parameters/Findings/JS Assets** 탭에서 Ctrl/Shift로 여러 행을 고른 뒤 우클릭 **Send N
selected with Match & Replace…**로 헤더/쿠키 값 치환(예: Cookie 값 통째로 교체) 또는 요청 원문 전체
문자열/정규식 치환(Burp Match and Replace와 동일 개념, `$1` 등 정규식 백레퍼런스 지원)을 적용해 일괄
재전송. **규칙을 여러 개 추가해 순서대로 체이닝 가능**(예: 헤더 교체 후 원문 치환까지 한 번에) —
미리보기는 항상 전체 체인을 적용한 최종 결과를 보여줌. **Settings에서 먼저 켜야**(기본 꺼짐) 메뉴가
동작하고, 켜져 있어도 **실행마다 확인 다이얼로그**(첫 번째 선택 요청에 규칙 적용한 전/후 미리보기
포함)가 필수 — Bruteforce처럼 "다시 묻지 않기" 없음. 스코프 밖 대상은 자동 제외. 결과는 **Match &
Replace 탭**에서 호스트·상태·길이·에러 요약 + 행 선택 시 실제 전송된 request/response 상세 확인
가능(세션 내 보관, State Export/Import 대상 아님).

### Snapshot Diff
**Settings → Backup / State**에서 내보낸 State 파일을 **Load comparison state file…** 버튼으로 불러와
현재 라이브 데이터와 비교 — Endpoints/Parameters/Findings/JS Assets/Tech 5개 카테고리별로 새로 생긴
(+)/사라진(−) 항목을 표로 보여줌. 다른 탭과 달리 상시 갱신되지 않고, 파일을 불러올 때만 그 시점
기준으로 1회 비교(라이브 데이터는 건드리지 않음). 같은 항목의 내용이 바뀐 경우(상태 코드 변경 등)는
탐지하지 않음 — 추가/삭제만.

### Settings
스코프·패시브 토글·커스텀 탐지 규칙·Ingest·내보내기·State 백업. 모든 설정은 **Burp 재시작 후에도
유지**(extension preferences에 저장). **Remove out-of-scope hosts…**로 현재 스코프(Burp Scope +
include/exclude 정규식) 밖의 호스트를 한 번에 찾아서 일괄 삭제 — 사이트맵 전체를 ingest한 뒤 불필요한
호스트가 섞여 들어왔을 때 유용(Scope Mode가 "All"이면 스코프 밖이 없으므로 항상 "없음"으로 나옴).
내보내기(HTML/Markdown/JSON/SARIF) 옆 **Confirmed only / Exclude false positives / Bookmarked only**
체크박스로 리포트 범위를 좁힐 수 있음 — **Bookmarked only는 Findings뿐 아니라 Endpoints/Parameters/
JS/Tech 전 섹션에 적용**. **Match & Replace bulk send** 섹션에서 기능 켜기(기본 꺼짐) + 요청 간
지연·동시성 스로틀 조절.

### 탐지 항목 상세
API 키/토큰·JWT·인증 헤더·스토리지 URL 등 **시크릿**(응답 본문뿐 아니라 **쿠키 값**도 스캔 — 쿠키로
오는 JWT 등도 잡힘), **PII**(주민번호·카드·휴대폰), URL 노출 시크릿·오픈 리다이렉트·반사 XSS 후보,
스택트레이스/SQL 에러 등 응답 시그니처, CORS(와일드카드·크리덴셜·Origin 미검증·Allow-Methods/Headers
와일드카드)·쿠키·CSP·캐시·혼합 콘텐츠 **미스컨피그**, 노출 파일(`.env`·`.git` 등)·백업, 디버그/진단
경로(bruteforce), 권한 단서, **OpenAPI/Swagger 스펙**(JSON·**YAML 둘 다**)·**GraphQL
introspection**(스키마를 실제로 파싱해 타입.필드를 엔드포인트/파라미터로 등록), **소스맵(.map) 노출**
(JS 내 `sourceMappingURL` 참조 / 캡처된 `.map`의 원본 소스 목록), 주석, 누락된 보안 헤더. (화면에선
원문 확인·복사 가능, 리포트에선 마스킹)

### 공통 기능 상세
한/영·본문 검색(정규식·다중 AND·제외·컬럼 지정), 정렬 3단계(오름 → 내림 → 기본), CSV 내보내기, 행
우클릭 Copy/Open/Repeater/Intruder/curl. Request/Response 뷰어가 있는 탭(Endpoints·Parameters·
Findings·JS Assets)에서 JS 응답이면 **Beautify JS** 토글로 한 줄로 압축된 minified 본문을 줄바꿈·
들여쓰기해서 열람(화면 표시만 바꿈 — 캡처된 응답 자체나 탐지 로직에는 영향 없음).

**정렬**: 컬럼 헤더 클릭 시 그 컬럼만으로 정렬(오름차순 → 내림차순 → 정렬 해제로 순환, 다른 컬럼의
기존 정렬은 대체됨). **`Shift`+클릭**하면 다중 컬럼 정렬 — 클릭한 컬럼이 1순위가 되고 이전 정렬은
2·3순위로 유지됨(예: Host 클릭 후 `Shift`+Status 클릭 → Host 안에서 Status로 정렬), 헤더에 "2"·"3"
같은 작은 숫자로 순위 표시.

**체크박스 다중값 필터**(Endpoints/Parameters의 Method·Status·Type·Location·Class, Findings/Tech의
Host): 검색창 옆 필터 버튼을 누르면 그 컬럼에 현재 존재하는 모든 값이 체크박스로 나열됨 — 체크 해제한
값만 숨김(여러 개를 연달아 체크/해제 가능, 팝업이 자동으로 안 닫힘). 데이터가 갱신되면 목록도 자동으로
최신화.

인벤토리 탭(Endpoints·Parameters·Findings·JS Assets·Tech)은 행 우클릭 **★ Bookmark / Edit note…**
(또는 `Ctrl+B`)로 북마크·메모 가능 — Burp 재시작 후에도 유지, `★ only` 체크박스로 북마크된 행만
필터, State Export/Import에도 보존.

**키보드 단축키**: `Ctrl+1`~`Ctrl+9` 탭 전환(마지막 Settings 탭은 제외), `Ctrl+F` 현재 탭 검색창
포커스, **`Ctrl+Shift+F` 글로벌 검색**(Endpoints/Parameters/Findings/JS Assets/Tech 5개 탭을 한 번에
검색해 결과 목록에서 바로 해당 탭·행으로 이동), 검색창에서 `Esc`로
검색어 지우기.

**다크테마**: Burp의 라이트/다크 테마를 따라감(실시간 전환 반영, 최대 1초 지연).

**줄무늬 배경**: Dashboard·Bruteforce를 포함한 모든 표가 한 줄씩 배경을 살짝 다르게 표시해 행을
눈으로 따라가기 쉽게 함. Endpoints의 **Status** 컬럼은 2xx(녹색)·5xx(주황) 등 상태 코드별로도 색상
구분.

## 변경 이력

버전별 변경사항과 빌드된 JAR은 **[GitHub Releases](https://github.com/9u4a/reconhub/releases)** 참고.
