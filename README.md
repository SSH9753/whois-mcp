# whois-mcp

KISA 후이즈 검색 API(공공데이터포털)를 사용해 **국가도메인(.kr / .한국)과 IP 주소의 WHOIS 정보**를 조회하는 MCP 서버입니다.



## 기능

- 단건·다건·파일 단위 조회, 결과를 CSV(엑셀용 UTF-8 BOM) / JSONL 로 저장
- 입력 자동 정규화: 디팽 표기(`hxxps://evil[.]co[.]kr`), URL → 호스트, 대소문자·끝의 점, 중복 제거
- 조회 대상이 아닌 항목은 API를 호출하지 않고 제외: 비-.kr 도메인, 사설/예약 IP, CIDR
- 미등록 도메인은 `not_found` 로 구분
- 동시 요청 수 제한, 일시 오류 재시도, 인증키 오류·트래픽 초과 시 대량 조회 조기 중단
- 대량 조회 요약: 상태별 건수, 상위 등록대행자·등록인·ISP, 국가, **최근 N일 내 신규 등록 도메인**

## 준비물

1. **uv** — [설치 안내](https://docs.astral.sh/uv/getting-started/installation/). Python은 uv가 알아서 받습니다(3.10 이상).
   Windows: `winget install --id=astral-sh.uv -e` 또는 PowerShell에서 `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
2. **공공데이터포털 인증키** — [data.go.kr](https://www.data.go.kr)에서 '후이즈'로 검색해 한국인터넷진흥원 후이즈 검색 서비스를 활용신청하고, 마이페이지에서 인증키를 확인합니다.
   **일반 인증키(Decoding)** 를 넣으세요. 이 서버가 요청할 때 URL 인코딩을 하므로 Encoding 키를 넣으면 이중 인코딩되어 인증에 실패할 수 있습니다.

## 설치 (clone 방식)

```bash
git clone https://github.com/SSH9753/whois-mcp.git
```

Claude Desktop 설정 파일(`claude_desktop_config.json`)에 추가합니다. Windows는 경로의 `\` 를 `\\` 로 적어야 합니다.

```json
{
  "mcpServers": {
    "whois": {
      "command": "uv",
      "args": ["--directory", "C:\\Users\\<사용자>\\whois-mcp", "run", "whois-mcp"],
      "env": {
        "WHOIS_SERVICE_KEY": "발급받은_인증키"
      }
    }
  }
}
```

Claude Desktop을 재시작하면 처음 실행할 때 uv가 의존성을 설치합니다. **업데이트**는 저장소 폴더에서 `git pull` 하면 됩니다.

### 대안: clone 없이 실행

저장소를 받지 않고 GitHub에서 바로 실행할 수도 있습니다(git 필요). 업데이트하려면 `uv cache clean whois-mcp` 를 실행하거나 `@main` 대신 특정 태그나 커밋을 지정합니다.

```json
"whois": {
  "command": "uvx",
  "args": ["--from", "git+https://github.com/SSH9753/whois-mcp@main", "whois-mcp"],
  "env": { "WHOIS_SERVICE_KEY": "발급받은_인증키" }
}
```

## 도구

| 도구 | 용도 | API 호출 |
|---|---|---|
| `whois_lookup` | 도메인/IP/URL 하나 조회 | 1회 |
| `whois_bulk_lookup` | 목록 조회 (기본 최대 100건), 결과 전체 반환 | 건수만큼 |
| `whois_preview_file` | 목록 파일 사전 분석: 유효·제외·중복 건수, 필요한 호출 수 | 없음 |
| `whois_bulk_lookup_file` | 목록 파일 전체를 조회해 CSV/JSONL로 저장하고 **요약만** 반환 | 건수만큼 |

목록 파일은 한 줄에 하나씩 적습니다. `#` 로 시작하는 줄은 주석이고, CSV/TSV는 첫 열만 씁니다. UTF-8과 CP949 모두 읽습니다.
출력 경로를 생략하면 입력 파일 옆에 `<이름>_whois_<시각>.csv` 로 저장합니다.

사용 예: *"C:\work\phishing_0921.txt 에 있는 도메인들 whois 조회해서 CSV로 저장하고, 최근 7일 안에 등록된 것만 알려줘"*

### 결과 상태값

| status | 의미 |
|---|---|
| `ok` | 조회 성공 |
| `not_found` | 등록 정보 없음 (미등록 도메인 등) |
| `skipped` | 조회 대상 아님 (비-.kr 도메인, 사설 IP). API 미호출 |
| `invalid` | 도메인/IP 형식 아님. API 미호출 |
| `error` | API·네트워크 오류 (`error` 필드에 사유) |

## 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `WHOIS_SERVICE_KEY` | (필수) | 공공데이터포털 인증키 |
| `WHOIS_CONCURRENCY` | `5` | 동시 요청 수 |
| `WHOIS_TIMEOUT` | `10` | 요청 타임아웃(초) |
| `WHOIS_MAX_RETRIES` | `2` | 일시 오류 재시도 횟수 |
| `WHOIS_MAX_FILE_ITEMS` | `50000` | 파일 조회 최대 건수 |
| `WHOIS_MAX_INLINE_ITEMS` | `100` | `whois_bulk_lookup` 최대 건수 |
| `WHOIS_API_BASE` | `http://apis.data.go.kr/B551505/whois` | API 기본 주소 |

공공데이터포털 API에는 계정별 일일 트래픽 한도가 있습니다. 대량 조회 전에 `whois_preview_file` 로 호출 수를 확인하세요.


## 개발

```bash
uv sync
uv run pytest
uv run whois-mcp --transport streamable-http --port 8000   # HTTP 모드로 직접 띄워 테스트
```

## 라이선스

MIT
