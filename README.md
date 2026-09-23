# ReconHub — Burp Suite 진단 정보 정리 확장

## 개요

**ReconHub**는 Burp에 쌓인 **Proxy History / Site Map**을 순회해 진단에 필요한 정보를 추출·정리하는
Burp Suite 확장(Montoya API, Java)입니다. 엔드포인트·파라미터 인벤토리, 민감정보·미스컨피그 탐지,
JavaScript 수집·분석, 기술 핑거프린팅을 수행하고 결과를 **JSON / HTML / Markdown / SARIF 리포트**와
재적재 가능한 **State 백업**으로 내보냅니다. 기본은 이미 캡처된 트래픽만 사용하는 **수동(passive)
분석**이며, 유일한 예외인 **Bruteforce 탭(알려진 경로 탐색)만 ACTIVE**(대상에 요청 전송) — 별도
on/off 토글은 없고, **호스트 우클릭 → 대상 주소를 확인·수정하는 확인 다이얼로그**가 실행마다 반드시
거쳐야 하는 게이트입니다.

## 기능

| 탭 | 설명 |
|----|------|
| **Dashboard** | 카운트·심각도 요약, **호스트 스코어카드**(선택 시 심각도별·누락 보안헤더 상세), Top findings·주목 엔드포인트·파라미터 클래스. 우클릭으로 다른 탭에서 필터링해 보기 |
| **Endpoints** | method+정규화 URL로 dedup한 인벤토리(인증 관찰 Auth 컬럼 포함), 행 선택 시 원문 Request/Response. **XML/SOAP** Content-Type이면 우클릭 **View payload cheatsheet (XXE)…** 제공 |
| **Parameters** | 엔드포인트별 파라미터(query/body/JSON/cookie) + 취약점 후보 **Class** 자동 분류(IDOR·Redirect/SSRF·File/Path·SQLi/Sort·Command·**SSTI**). 우클릭 **Payload cheatsheet ▸**로 자동 제안 클래스는 원클릭, **전체 클래스도 항상 수동으로 직접 선택 가능**(Basic/Bypass·우회 페이로드, Intruder에 클래스당 2세트 등록). **JSON 파라미터**는 Prototype Pollution, **직렬화 값처럼 보이는 파라미터**(Java/PHP serialize·ViewState)는 Deserialization이 이름과 무관하게 자동 제안 |
| **Findings** | 시크릿·PII·미스컨피그 등을 심각도·**카테고리**로 집계(필터·트리아지·JWT 디코드, 행 선택 시 원문). 우클릭 **Payload cheatsheet ▸**로 반사 XSS·오픈 리다이렉트는 자동 제안, **전체 클래스도 수동 선택 가능** |
| **JS Assets** | JS 수집(SHA-256 dedup·옵션 저장) + 내부 엔드포인트·시크릿 추출. 해시 이름 코드-스플릿 청크를 열어보지 않고 구분할 수 있는 **Preview** 컬럼(감지된 엔드포인트 샘플, 없으면 코드 스니펫), 행 선택 시 **Response 탭**에서 캡처된 응답 원문 확인(임포트된 파일은 없음). 트래픽에 안 잡힌 파일은 **Import JS file(s)…**로 로컬에서 불러와 동일 분석 |
| **Tech** | 호스트별 기술 식별 + 보안 헤더 누락 체크(Findings에도 동일 항목이 LOW로 집계) |
| **Bruteforce** ⚠**ACTIVE** | 알려진 경로(관리자 패널·API 문서·노출 파일·CI/CD·IDE 아티팩트 등, 내장 워드리스트 약 380개) 탐색. **Hits 탭**에서 확인된 hit을 바로 표로 확인(호스트·경로·상태·길이·태그, 우클릭 Copy/Open in browser). 스로틀(지연·동시성·호스트당 상한) 조절, **Activity log**에 보낸 경로·응답(상태·길이·유사도)을 실시간 기록. Dashboard/Endpoints/Parameters/Tech/Findings에서 호스트 우클릭 → **확인 다이얼로그에서 대상 주소(스킴·포트 포함) 직접 수정 + 매 실행마다 확인**(이게 유일한 게이트) — 기본 스킴은 그 호스트에서 **이미 관찰된 트래픽**을 참고해 자동 선택(http만 관찰된 호스트에 https를 강제해 전부 실패하는 상황 방지). Soft-404 판정은 **본문 유사도 기반**(경로가 그대로 echo되는 404 페이지에도 오탐 없음). 결과는 Endpoints(Source=bruteforce)·Findings 탭에도 반영, Jobs/Hits는 **State Export/Import에도 완료 기록으로 보존** |
| **Settings** | 스코프·패시브 토글·커스텀 탐지 규칙·Ingest·내보내기·State 백업. 모든 설정은 **Burp 재시작 후에도 유지**(extension preferences에 저장) |

**탐지 항목**: API 키/토큰·JWT·인증 헤더·스토리지 URL 등 **시크릿**(응답 본문뿐 아니라 **쿠키 값**도 스캔
— 쿠키로 오는 JWT 등도 잡힘), **PII**(주민번호·카드·휴대폰), URL 노출 시크릿·오픈 리다이렉트·반사 XSS
후보, 스택트레이스/SQL 에러 등 응답 시그니처, CORS(와일드카드·크리덴셜·Origin 미검증·Allow-Methods/
Headers 와일드카드)·쿠키·CSP·캐시·혼합 콘텐츠 **미스컨피그**, 노출 파일(`.env`·`.git` 등)·백업,
디버그/진단 경로(bruteforce), 권한 단서, **OpenAPI/Swagger 스펙**(JSON·**YAML 둘 다**)·**GraphQL
introspection**(스키마를 실제로 파싱해 타입.필드를 엔드포인트/파라미터로 등록), **소스맵(.map) 노출**
(JS 내 `sourceMappingURL` 참조 / 캡처된 `.map`의 원본 소스 목록), 주석, 누락된 보안 헤더. (화면에선
원문 확인·복사 가능, 리포트에선 마스킹)

**모든 탭 공통**: 한/영·본문 검색(정규식·다중 AND·제외·컬럼 지정), 정렬 3단계(오름 → 내림 → 기본),
CSV 내보내기, 행 우클릭 Copy/Open/Repeater/Intruder/curl. Request/Response 뷰어가 있는 탭(Endpoints·
Parameters·Findings·JS Assets)에서 JS 응답이면 **Beautify JS** 토글로 한 줄로 압축된 minified 본문을
줄바꿈·들여쓰기해서 열람(화면 표시만 바꿈 — 캡처된 응답 자체나 탐지 로직에는 영향 없음). 인벤토리
탭(Endpoints·Parameters·Findings·JS Assets·Tech)은 행 우클릭 **★ Bookmark / Edit note…**(또는
`Ctrl+B`)로 북마크·메모 가능 — Burp 재시작 후에도 유지, `★ only` 체크박스로 북마크된 행만 필터,
State Export/Import에도 보존. **키보드 단축키**: `Ctrl+1`~`Ctrl+8`로 탭 전환, `Ctrl+F`로 현재 탭
검색창 포커스, 검색창에서 `Esc`로 검색어 지우기. **다크테마**: Burp의 라이트/다크 테마를 따라감(실시간
전환 반영, 최대 1초 지연).

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

## 변경 이력

버전별 변경사항과 빌드된 JAR은 **[GitHub Releases](https://github.com/9u4a/reconhub/releases)** 참고.
