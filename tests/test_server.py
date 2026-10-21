"""MCP 프로토콜 수준 테스트: 인프로세스 클라이언트로 서버 도구를 호출한다."""

from __future__ import annotations

import csv

import httpx
import pytest
from mcp import Client

from whois_mcp import server as srv
from whois_mcp.client import WhoisApiClient

from .conftest import DOMAIN_OK


@pytest.fixture
def patched(monkeypatch, api):
    monkeypatch.setenv("WHOIS_SERVICE_KEY", "test-key")
    monkeypatch.setenv("WHOIS_MAX_INLINE_ITEMS", "5")
    monkeypatch.setattr(
        srv, "_make_client", lambda s: WhoisApiClient(s, transport=httpx.MockTransport(api.handler))
    )
    return api


async def test_list_tools(patched):
    async with Client(srv.mcp) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == {"whois_lookup", "whois_bulk_lookup", "whois_preview_file", "whois_bulk_lookup_file"}


async def test_lookup_tool(patched):
    patched.responses["kisa.or.kr"] = (200, DOMAIN_OK)
    async with Client(srv.mcp) as c:
        res = await c.call_tool("whois_lookup", {"query": "kisa[.]or[.]kr"})
    assert not res.is_error
    assert res.structured_content["status"] == "ok"
    assert res.structured_content["data"]["registrar"] == "한국인터넷진흥원"


async def test_bulk_inline_limit(patched):
    async with Client(srv.mcp) as c:
        res = await c.call_tool("whois_bulk_lookup", {"queries": [f"d{i}.kr" for i in range(6)]})
    assert res.is_error


async def test_missing_key(monkeypatch, api):
    monkeypatch.delenv("WHOIS_SERVICE_KEY", raising=False)
    async with Client(srv.mcp) as c:
        res = await c.call_tool("whois_lookup", {"query": "kisa.or.kr"})
    assert res.is_error
    assert "WHOIS_SERVICE_KEY" in res.content[0].text


async def test_file_flow(patched, tmp_path):
    patched.responses["kisa.or.kr"] = (200, DOMAIN_OK)
    src = tmp_path / "list.txt"
    src.write_text("kisa.or.kr\nhxxp://kisa[.]or[.]kr\n211.252.150.11\ngoogle.com\n10.0.0.1\nnope\n", encoding="utf-8")
    async with Client(srv.mcp) as c:
        pre = (await c.call_tool("whois_preview_file", {"input_path": str(src)})).structured_content
        assert pre["api_calls_needed"] == 2 and pre["duplicates_removed"] == 1
        assert patched.calls == []  # 미리보기는 API 미호출

        out = tmp_path / "out.csv"
        res = await c.call_tool("whois_bulk_lookup_file", {"input_path": str(src), "output_path": str(out)})
    body = res.structured_content
    assert not res.is_error, res.content
    assert body["records_saved"] == 5
    assert body["summary"]["by_status"]["ok"] == 2
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert {r["status"] for r in rows} == {"ok", "skipped", "invalid"}
    assert len(patched.calls) == 2
