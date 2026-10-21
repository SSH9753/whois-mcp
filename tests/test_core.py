from __future__ import annotations

import csv
import json

import pytest

from whois_mcp.client import WhoisResult
from whois_mcp.files import read_query_file, summarize, write_results
from whois_mcp.normalize import dedupe, normalize
from whois_mcp.parsers import ApiGatewayError, normalize_date, parse_domain, parse_ip

from .conftest import DOMAIN_NOT_FOUND, DOMAIN_OK, GATEWAY_KEY_ERROR, IP_OK


# ----------------------------------------------------------- normalize --- #
@pytest.mark.parametrize(
    "raw, kind, value",
    [
        ("kisa.or.kr", "domain", "kisa.or.kr"),
        ("hxxps://evil-login[.]co[.]kr/path?a=1", "domain", "evil-login.co.kr"),
        ("KISA.OR.KR.", "domain", "kisa.or.kr"),
        ("example.kr:8443/login", "domain", "example.kr"),
        ("한국인터넷진흥원.한국", "domain", "한국인터넷진흥원.한국"),
        ("211.252.150[.]11", "ip", "211.252.150.11"),
        ("http://[2001:4860:4860::8888]:443/", "ip", "2001:4860:4860::8888"),
        ("google.com", "skipped", "google.com"),
        ("192.168.0.1", "skipped", "192.168.0.1"),
        ("1.2.3.0/24", "invalid", "1.2.3.0/24"),
        ("not a domain", "invalid", None),
        ("", "invalid", ""),
    ],
)
def test_normalize(raw, kind, value):
    q = normalize(raw)
    assert q.kind == kind
    if value is not None:
        assert q.value == value


def test_normalize_kr_only_off():
    assert normalize("google.com", kr_only=False).kind == "domain"


def test_dedupe():
    items, dup = dedupe([normalize(x) for x in ["a.kr", "A.KR", "hxxp://a[.]kr", "b.kr", "bad", "bad"]])
    assert dup == 2
    assert [q.value for q in items if q.kind == "domain"] == ["a.kr", "b.kr"]
    assert sum(q.kind == "invalid" for q in items) == 2  # 오류 항목은 제거하지 않음


# ------------------------------------------------------------- parsers --- #
@pytest.mark.parametrize(
    "raw, expected",
    [("2025. 05. 09.", "2025-05-09"), ("20001205", "2000-12-05"), ("2024-1-3", "2024-01-03"), (None, None), ("미정", "미정")],
)
def test_normalize_date(raw, expected):
    assert normalize_date(raw) == expected


def test_parse_domain_ok():
    status, data, err = parse_domain(DOMAIN_OK)
    assert status == "ok" and err is None
    assert data["registrant"] == "한국인터넷진흥원"
    assert data["registrant_en"] == "Korea Internet & Security Agency"  # 이중 이스케이프 해제
    assert data["registered"] == "1996-07-20"
    assert data["nameservers"] == ["center.kisa.or.kr", "hera.kisa.or.kr"]
    assert data["status"] == ["serverDeleteProhibited", "serverTransferProhibited"]


def test_parse_domain_not_found():
    assert parse_domain(DOMAIN_NOT_FOUND)[0] == "not_found"


def test_parse_ip_ok():
    status, data, _ = parse_ip(IP_OK)
    assert status == "ok"
    assert data["registry"] == "KRNIC" and data["country"] == "KR"
    assert data["isp"]["ko"]["orgName"] == "주식회사 케이티"
    assert data["isp"]["ko"]["regDate"] == "2000-12-05"
    assert data["isp"]["ko"]["contact"]["email"] == "kornet_ip@kt.com"
    assert data["isp"]["en"]["orgName"] == "Korea Telecom"


def test_gateway_error_is_fatal():
    with pytest.raises(ApiGatewayError) as ei:
        parse_domain(GATEWAY_KEY_ERROR)
    assert ei.value.fatal and ei.value.code == "30"


# -------------------------------------------------------------- client --- #
async def test_lookup_ok_and_skip(client, api):
    api.responses["kisa.or.kr"] = (200, DOMAIN_OK)
    r = await client.lookup("hxxps://kisa[.]or[.]kr/")
    assert r.status == "ok" and r.query == "kisa.or.kr"
    r2 = await client.lookup("google.com")
    assert r2.status == "skipped"
    assert api.calls == [("domain_name", "kisa.or.kr")]  # 비-.kr 은 API 호출 안 함


async def test_retry_then_error(client, api):
    api.responses["flaky.kr"] = (503, "busy")
    r = await client.lookup("flaky.kr")
    assert r.status == "error" and "HTTP 503" in r.error
    assert len(api.calls) == 2  # max_retries=1 → 총 2회


async def test_lookup_many_aborts_on_fatal(client, api):
    api.default_domain = (200, GATEWAY_KEY_ERROR)
    qs = [normalize(f"d{i}.kr") for i in range(20)]
    results, aborted = await client.lookup_many(qs)
    assert aborted and "SERVICE_KEY" in aborted
    assert len(results) == 20
    assert all(r.status == "error" for r in results)
    assert len(api.calls) < 20  # 나머지는 취소됨


# --------------------------------------------------------------- files --- #
def test_read_query_file(tmp_path):
    p = tmp_path / "in.csv"
    p.write_text("# 주석\nkisa.or.kr,메모\n\n1.1.1.1\tx\nb.kr\n", encoding="utf-8")
    items, truncated = read_query_file(p, limit=10)
    assert items == ["kisa.or.kr", "1.1.1.1", "b.kr"] and not truncated
    items, truncated = read_query_file(p, limit=2)
    assert len(items) == 2 and truncated


def test_read_query_file_cp949(tmp_path):
    p = tmp_path / "in.txt"
    p.write_bytes("한국인터넷진흥원.한국\n".encode("cp949"))
    assert read_query_file(p, 10)[0] == ["한국인터넷진흥원.한국"]


def _results():
    _, d, _ = parse_domain(DOMAIN_OK)
    _, ip, _ = parse_ip(IP_OK)
    return [
        WhoisResult("kisa.or.kr", "kisa.or.kr", "domain", "ok", d),
        WhoisResult("211.252.150.11", "211.252.150.11", "ip", "ok", ip),
        WhoisResult("x.kr", "x.kr", "domain", "error", error="HTTP 500"),  # 기존 코드에서 CSV 저장을 깨던 케이스
        WhoisResult("g.com", "g.com", "skipped", "skipped", error="국가도메인 아님"),
    ]


def test_write_csv_with_errors(tmp_path):
    out = tmp_path / "o.csv"
    assert write_results(_results(), out, "csv") == 4
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows[0]["domain_status"].startswith("serverDelete")
    assert rows[0]["nameservers"] == "center.kisa.or.kr; hera.kisa.or.kr"
    assert rows[1]["isp_org"] == "주식회사 케이티"
    assert rows[2]["error"] == "HTTP 500"


def test_write_jsonl(tmp_path):
    out = tmp_path / "o.jsonl"
    write_results(_results(), out, "jsonl")
    lines = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["data"]["registrant"] == "한국인터넷진흥원"


def test_summarize():
    s = summarize(_results(), recent_days=30)
    assert s["by_status"] == {"ok": 2, "error": 1, "skipped": 1}
    assert s["top_isps"] == [("주식회사 케이티", 1)]
    assert s["registered_within_30d"]["count"] == 0
