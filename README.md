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
| **Endpoints** | method + 정규화 URL로 dedup한 엔드포인트 인벤토리. 행 선택 시 하단에 Request/Response 표시, 우클릭 → **Send to Repeater** |
| **Parameters** | 엔드포인트별 파라미터(query/body/JSON/cookie) — 경로·유형·예시값·반사 여부·Seen. 행 선택 시 매칭 Request/Response 표시 |
| **Findings** | 응답·JS에서 탐지한 시크릿/민감정보(AWS·Google·GitHub·Slack 키, JWT, private key, S3 버킷, 이메일, 내부 IP 등), 심각도 정렬 |
| **JS Assets** | 수집한 JS를 SHA-256 해시로 dedup 저장, JS 내 엔드포인트·시크릿 추출. 출처 JS 파일 기록 |
| **Tech** | 헤더/쿠키/JS 라이브러리 기반 호스트별 기술 식별 + 보안 헤더 누락 체크리스트 |
| **Settings** | 스코프 모드, JS 저장 폴더, 라이브 캡처/시크릿 스캔 토글, Ingest Site Map, Clear, Export JSON/HTML |

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
