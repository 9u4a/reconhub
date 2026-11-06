# ReconHub — Burp Suite 진단 정보 정리 확장

[![release](https://img.shields.io/github/v/release/9u4a/reconhub)](https://github.com/9u4a/reconhub/releases)
[![test](https://github.com/9u4a/reconhub/actions/workflows/test.yml/badge.svg)](https://github.com/9u4a/reconhub/actions/workflows/test.yml)
[![license](https://img.shields.io/github/license/9u4a/reconhub)](LICENSE)

## 개요

**ReconHub**는 Burp의 **Proxy History / Site Map**을 읽어 엔드포인트·파라미터 인벤토리, 민감정보·설정
오류, JS 분석 결과를 정리하고 **JSON/HTML/Markdown/SARIF 리포트**로 내보내는 Burp Suite 확장입니다
(Montoya API, Java 17). 기본은 이미 캡처된 트래픽만 분석하며, 대상 서버에 새 요청을 보내지 않습니다.

| 진단하며 겪은 문제 | 만든 기능 |
|---|---|
| Proxy History의 엔드포인트·파라미터를 손으로 정리 | 인벤토리 자동 정리, 값 모양(숫자 ID·UUID·URL)으로 IDOR·SSRF 후보 분류 |
| 진단이 길어지면 이미 본 곳을 다시 확인 | 북마크·메모, Snapshot Diff, 요청해 보지 않은 경로만 보는 Untested only |
| JS 안의 키 같은 민감정보를 찾는 데 오래 걸림 | JS 정적 분석: 시크릿·암호화 키·IV 탐지, DOM XSS source → sink |

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
| **JS Assets** | JS 파일 수집·분석, 라이브러리·서드파티·빈 청크 자동 숨김, 파일별 Risk 순 정렬 |
| **JS Analysis** | JS 탐지 결과(암복호화·권한·DOM XSS·설정·API 호출·민감 경로·숨은 파라미터)를 번들을 가로질러 위험한 파일 순으로 표시, 실제 호출 여부(**Seen**)와 **Untested only** |
| **Tech** | 호스트별 기술 식별 + 보안 헤더 체크 |
| **Match & Replace** ⚠**ACTIVE** | 선택한 행에 치환 규칙(체이닝 가능)을 적용해 재전송. 세션 프리셋(인증 제거 / 다른 계정)과 원본 대비 **Verdict**(Same·Different·Blocked)로 권한 검증 |
| **Snapshot Diff** | 저장한 State 파일과 현재 데이터를 비교해 새로 생긴/사라진/바뀐 항목 표시 |
| **Settings** | 스코프·규칙·Ingest·내보내기·State 백업, 스코프 밖 호스트 일괄 삭제, Match & Replace 켜기/스로틀 |

**공통**: 검색(정규식·AND·본문)·다중 컬럼 정렬·체크박스 필터·CSV 내보내기·우클릭 Copy/Repeater/Intruder/curl·
JS Beautify·북마크/메모·키보드 단축키·다크테마 대응.

탭별 상세 동작과 탐지 항목 전체 목록은 **[docs/FEATURES.md](docs/FEATURES.md)** 참고.

## 사용법

**요구 사항**: Burp Suite Community/Professional(Montoya API 2023.12.1 이상 지원 버전), Java 17+

**빌드** (Gradle wrapper 포함):

```bash
./gradlew shadowJar        # Windows: gradlew.bat shadowJar
```

산출물 `build/libs/reconhub-<version>-all.jar`을 Burp **Extensions → Add → Java**로 로드
([Releases](https://github.com/9u4a/reconhub/releases)에서 빌드된 JAR 직접 다운로드도 가능).

**기본 흐름**: Target → Scope 등록 → **Settings → Ingest Site Map**(또는 Auto-ingest·Live capture)로
분석 → 각 탭에서 확인(행 선택 시 하단 원문 Request/Response) → **Findings** 우클릭으로 트리아지 →
Settings에서 **JSON/HTML/Markdown/SARIF** 리포트·워드리스트·**State Export/Import** 내보내기.
특정 요청만 취합하려면 다른 Burp 탭에서 우클릭 **Send to ReconHub**.

## 변경 이력

버전별 변경사항과 빌드된 JAR은 **[GitHub Releases](https://github.com/9u4a/reconhub/releases)** 참고.
