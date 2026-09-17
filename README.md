# ReconHub — Burp Suite 진단 정보 정리 확장

## 개요

**ReconHub**는 Burp에 쌓인 **Proxy History / Site Map**을 순회해 진단에 필요한 정보를 추출·정리하는
Burp Suite 확장(Montoya API, Java)입니다. 엔드포인트·파라미터 인벤토리, 민감정보·미스컨피그 탐지,
JavaScript 수집·분석, 기술 핑거프린팅을 수행하고 결과를 **JSON / HTML / Markdown / SARIF 리포트**와
재적재 가능한 **State 백업**으로 내보냅니다. 이미 캡처된 트래픽만 사용하는 **수동(passive) 분석**이며,
대상 서버에 직접 트래픽을 발생시키지 않습니다.

## 기능

| 탭 | 설명 |
|----|------|
| **Dashboard** | 카운트·심각도 요약, **호스트 스코어카드**(선택 시 심각도별·누락 보안헤더 상세), Top findings·주목 엔드포인트·파라미터 클래스. 우클릭으로 다른 탭에서 필터링해 보기 |
| **Endpoints** | method+정규화 URL로 dedup한 인벤토리(인증 관찰 Auth 컬럼 포함), 행 선택 시 원문 Request/Response |
| **Parameters** | 엔드포인트별 파라미터(query/body/JSON/cookie) + 취약점 후보 **Class** 자동 분류 |
| **Findings** | 시크릿·PII·미스컨피그 등을 심각도·**카테고리**로 집계(필터·트리아지·JWT 디코드, 행 선택 시 원문) |
| **JS Assets** | JS 수집(SHA-256 dedup·옵션 저장) + 내부 엔드포인트·시크릿 추출 |
| **Tech** | 호스트별 기술 식별 + 보안 헤더 누락 체크 |
| **Settings** | 스코프·패시브 토글·커스텀 탐지 규칙·Ingest·내보내기·State 백업 |

**탐지 항목**: API 키/토큰·JWT·인증 헤더·스토리지 URL 등 **시크릿**, **PII**(주민번호·카드·휴대폰),
URL 노출 시크릿·오픈 리다이렉트·반사 XSS 후보, 스택트레이스/SQL 에러 등 응답 시그니처,
CORS·쿠키·CSP·캐시·혼합 콘텐츠 **미스컨피그**, 노출 파일(`.env`·`.git` 등)·백업, 권한 단서,
OpenAPI/GraphQL, 주석. (화면에선 원문 확인·복사 가능, 리포트에선 마스킹)

**모든 탭 공통**: 한/영·본문 검색(정규식·다중 AND·제외·컬럼 지정), 정렬 3단계(오름 → 내림 → 기본),
CSV 내보내기, 행 우클릭 Copy/Open/Repeater/Intruder/curl.

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
