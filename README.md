# ReconHub — Burp Suite 진단 정보 정리 확장

[![test](https://github.com/9u4a/reconhub/actions/workflows/test.yml/badge.svg)](https://github.com/9u4a/reconhub/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**[⬇ 최신 JAR 다운로드 (Releases)](https://github.com/9u4a/reconhub/releases/latest)**

## 개요

**ReconHub**는 Burp의 **Proxy History / Site Map**을 읽어 엔드포인트·파라미터 인벤토리, 민감정보·설정
오류, JS 분석 결과를 정리하고 **JSON/HTML/Markdown/SARIF 리포트**로 내보내는 Burp Suite 확장입니다
(Montoya API, Java 17). 기본은 이미 캡처된 트래픽만 분석하며, 대상 서버에 새 요청을 보내지 않습니다.

![Parameters 탭: 파라미터별 취약점 후보 Class와 값 모양 분류](https://github.com/9u4a/reconhub/releases/download/reconhub-v0.57.0/reconhub-parameters.png)
<sub>호스트 정보는 모자이크 처리</sub>

| 진단하며 겪은 문제 | 만든 기능 |
|---|---|
| Proxy History의 엔드포인트·파라미터를 손으로 정리 | 인벤토리 자동 정리, 값 모양(숫자 ID·UUID·URL)으로 IDOR·SSRF 후보 분류 |
| 진단이 길어지면 이미 본 곳을 다시 확인 | 북마크·메모, Snapshot Diff, 요청해 보지 않은 경로만 보는 Untested only |
| JS 안의 키 같은 민감정보를 찾는 데 오래 걸림 | JS 정적 분석: 시크릿·암호화 키·IV 탐지, DOM XSS source → sink |
| 어떤 화면 기능이 어떤 API를 부르는지 JS를 읽어 추적 | Client Flows: 기능별 API 요청(메서드·경로·파라미터·인증) 지도, 권한·IDOR 테스트 대상 표시 |

**안전 설계**
- **PASSIVE 기본**: 캡처된 트래픽만 분석합니다.
- **ACTIVE는 Match & Replace 하나뿐이며 기본 꺼짐**: Settings에서 켜야 하고, 실행할 때마다 전·후
  미리보기와 확인을 거칩니다. 스코프 밖 대상은 자동으로 제외합니다.
- 저장한 다른 계정 세션은 메모리에만 두고, 리포트의 시크릿은 마스킹합니다.

> 허가받은 진단 범위 안에서만 사용하세요.

## 기능

| 탭 | 한 줄 설명 |
|----|------|
| **Host focus** (상단 바) | 호스트 하나를 고르면 Endpoints·Parameters·Findings가 그 호스트 행만 표시 |
| **Dashboard** | 요약 통계 + 호스트 스코어카드, 다른 탭으로 이동, 호스트 데이터 삭제 |
| **Endpoints** | 엔드포인트 인벤토리 (dedup, Auth 관찰) |
| **Parameters** | 파라미터 + 취약점 후보 Class 자동 분류(이름 + 값 모양: 숫자 ID·UUID→IDOR, URL→Redirect/SSRF 등) |
| **Findings** | 탐지 결과 심각도/카테고리 집계 + 트리아지, 모든 탐지에 **Hint**(어떻게 테스트할지) |
| **JS Assets** | JS 파일 수집·분석, 라이브러리·서드파티·빈 청크 자동 숨김, 파일별 Risk 순 정렬, 확증 못 한 매치는 파일별 **Notes**로, 상세는 Findings·Client Flows·Notes·Endpoints·File 탭별 정렬 표 |
| **JS Analysis** | 구조 분석으로 **확증된 Lead만** 표시(같은 함수·같은 변수로 이어진 DOM XSS source → sink, 권한 체크가 보호하는 경로, 암호화 호출에 들어가는 키·IV, 민감 경로·숨은 파라미터), 번들을 가로질러 위험한 파일 순, 실제 호출 여부(**Seen**)와 **Untested only** |
| **Client Flows** | JS에서 화면 기능 → API 요청 지도 추출: fetch·axios·XHR·jQuery 호출(앱 공통 래퍼 포함)마다 메서드·경로 템플릿·body/query 키·인증 헤더 출처·호출 함수·트리거(라우트·이벤트 핸들러), 실제 호출 여부(**Seen**)와 **Untested only**, IDOR·무인증 Hint, **Send template to Repeater**(전송 안 함) |
| **Tech** | 호스트별 기술 식별 + 보안 헤더 체크 |
| **Match & Replace** ⚠**ACTIVE** | 선택한 행을 **여러 세션으로 한 번에** 재전송(Original·No auth·저장한 계정 체크), 대상×세션 아무 조합이나 전·후 **diff 미리보기**, 스코프 밖·규칙 미적용·토큰 만료 사전 검사, 요청 수·예상 시간 표시, 추가 치환 규칙(체이닝). **Sessions** 패널: 수집된 트래픽에서 계정 자동 찾기, Burp 우클릭 **Save as ReconHub session**, 요청 붙여넣기로 인증 헤더·세션 쿠키 자동 식별(쿠키 단위 교체, JWT 만료 표시), 앱 공용 API 키(X-Api-Key 등)는 유지 선택. 결과는 **실행 목록**(진행률·취소·재실행)과 **엔드포인트×세션 매트릭스**(⚠Same = 권한 우회 의심, Blocked·Different·Error 칩 필터), 원본·재전송 응답 좌우 비교 |
| **Snapshot Diff** | 저장한 State 파일과 현재 데이터를 비교해 새로 생긴/사라진/바뀐 항목 표시 |
| **Settings** | 상단 Ingest 바 + General(스코프·수집·분석·메모리) / JavaScript / Findings(필터·사용자 규칙) / Match & Replace(켜기·스로틀) / Export & Data(리포트·워드리스트·State 백업·데이터 삭제) 탭 |

**공통**: 검색(정규식·AND·본문)·다중 컬럼 정렬·체크박스 필터·CSV 내보내기·우클릭 Copy/Repeater/Intruder/curl·
JS Beautify·북마크/메모·키보드 단축키·다크테마 대응.

| Findings: 탐지마다 "어떻게 테스트할지" Hint | JS Analysis: JS 탐지를 번들 가로질러 위험도 순으로 |
|---|---|
| ![Findings 탭](https://github.com/9u4a/reconhub/releases/download/reconhub-v0.57.0/reconhub-findings.png) | ![JS Analysis 탭](https://github.com/9u4a/reconhub/releases/download/reconhub-v0.57.0/reconhub-js-analysis.png) |

탭별 상세 동작과 탐지 항목 전체 목록은 **[docs/FEATURES.md](docs/FEATURES.md)** 참고.

## 사용법

**요구 사항**: Burp Suite Community/Professional(Montoya API 2023.12.1 이상 지원 버전), Java 17+

**빌드** (Gradle wrapper 포함):

```bash
./gradlew shadowJar        # Windows: gradlew.bat shadowJar
```

산출물 `build/libs/reconhub-<version>-all.jar`을 Burp **Extensions → Add → Java**로 로드
([Releases](https://github.com/9u4a/reconhub/releases)에서 빌드된 JAR 직접 다운로드도 가능).

**기본 흐름**: Target → Scope 등록 → **Settings 상단 Ingest Site Map**(또는 Auto-ingest·Live capture)로
분석 → 각 탭에서 확인(행 선택 시 하단 원문 Request/Response) → **Findings** 우클릭으로 트리아지 →
**Settings → Export & Data**에서 **JSON/HTML/Markdown/SARIF** 리포트·워드리스트·**State Export/Import**.
특정 요청만 취합하려면 다른 Burp 탭에서 우클릭 **Send to ReconHub**.

## 변경 이력

버전별 변경사항과 빌드된 JAR은 **[GitHub Releases](https://github.com/9u4a/reconhub/releases)** 참고.
