"""테스트 공통: 실측 응답 필드 구조를 본뜬 XML과 모의 API."""

from __future__ import annotations

import httpx
import pytest

from whois_mcp.client import WhoisApiClient
from whois_mcp.config import Settings

DOMAIN_OK = """<?xml version="1.0" encoding="UTF-8"?>
<response><whois><krdomain>
  <name>kisa.or.kr</name><regName>한국인터넷진흥원</regName>
  <addr>전라남도 나주시 진흥길 9</addr><post>58324</post>
  <adminName>도메인관리자</adminName><adminEmail>kisairm@kisa.or.kr</adminEmail><adminPhone>1433-25</adminPhone>
  <lastUpdatedDate>2025. 05. 09.</lastUpdatedDate><regDate>1996. 07. 20.</regDate><endDate>9999. 12. 31.</endDate>
  <infoYN>Y</infoYN>
  <domainStatus>serverDeleteProhibited</domainStatus><domainStatus>serverTransferProhibited</domainStatus>
  <agency>한국인터넷진흥원</agency><agency_url>http://www.kisa.or.kr</agency_url>
  <e_regName>Korea Internet &amp;amp; Security Agency</e_regName><e_agency>KISA</e_agency>
  <dnssec>signed</dnssec>
  <ns1>center.kisa.or.kr</ns1><ns1>hera.kisa.or.kr</ns1>
  <ip1>211.252.150.11</ip1><ip1>211.252.150.20</ip1>
</krdomain></whois></response>"""

DOMAIN_NOT_FOUND = """<response><whois><krdomain><name></name><domainStatus/></krdomain></whois></response>"""

IP_OK = """<response><whois>
  <query>211.252.150.11</query><queryType>IPv4</queryType><registry>KRNIC</registry><countryCode>KR</countryCode>
  <korean><ISP>
    <netInfo><range>211.252.144.0 - 211.252.151.255</range><prefix>/21</prefix><orgName>주식회사 케이티</orgName>
      <servName>KORNET</servName><regDate>20001205</regDate></netInfo>
    <techContact><name>IP주소 담당자</name><email>kornet_ip@kt.com</email></techContact>
  </ISP></korean>
  <english><ISP><netInfo><orgName>Korea Telecom</orgName><servName>KORNET</servName></netInfo></ISP></english>
</whois></response>"""

GATEWAY_KEY_ERROR = """<OpenAPI_ServiceResponse><cmmMsgHeader><errMsg>SERVICE ERROR</errMsg>
<returnAuthMsg>SERVICE_KEY_IS_NOT_REGISTERED_ERROR</returnAuthMsg><returnReasonCode>30</returnReasonCode>
</cmmMsgHeader></OpenAPI_ServiceResponse>"""


class FakeApi:
    """query 값별로 응답을 지정. 호출 기록을 남긴다."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.responses: dict[str, tuple[int, str]] = {}
        self.default_domain = (200, DOMAIN_NOT_FOUND)
        self.default_ip = (200, IP_OK)

    def handler(self, request: httpx.Request) -> httpx.Response:
        q = request.url.params["query"]
        endpoint = request.url.path.rsplit("/", 1)[-1]
        self.calls.append((endpoint, q))
        status, body = self.responses.get(
            q, self.default_ip if endpoint == "ip_address" else self.default_domain
        )
        return httpx.Response(status, text=body)


@pytest.fixture
def api() -> FakeApi:
    return FakeApi()


@pytest.fixture
def settings() -> Settings:
    return Settings(service_key="test-key", concurrency=3, max_retries=1, max_inline_items=10)


@pytest.fixture
async def client(api: FakeApi, settings: Settings):
    async with WhoisApiClient(settings, transport=httpx.MockTransport(api.handler)) as c:
        yield c
