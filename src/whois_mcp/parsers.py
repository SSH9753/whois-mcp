"""KISA 후이즈 API XML 응답 파서."""

from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from typing import Any


class ApiGatewayError(Exception):
    """data.go.kr 게이트웨이가 돌려준 오류(인증키, 트래픽 한도 등)."""

    def __init__(self, message: str, code: str | None = None, *, fatal: bool = False):
        super().__init__(message)
        self.code = code
        # fatal=True 면 이후 요청도 모두 실패하므로 대량 조회를 중단한다.
        self.fatal = fatal


class ParseError(Exception):
    pass


# data.go.kr 공통 게이트웨이 오류 메시지 중 '계속 시도해도 실패하는' 것들.
# (포털 공통 오류코드 문구 기준. 이 API 에서 전부 실제로 확인한 것은 아님)
_FATAL_MARKERS = (
    "SERVICE_KEY_IS_NOT_REGISTERED",
    "DEADLINE_HAS_EXPIRED",
    "UNREGISTERED_IP",
    "LIMITED_NUMBER_OF_SERVICE_REQUESTS",
    "SERVICE_ACCESS_DENIED",
)


def _clean(text: str | None) -> str | None:
    if text is None:
        return None
    t = html.unescape(text).strip()  # 응답에 '&amp;' 가 이중 이스케이프로 오는 경우가 있다
    return t or None


def _text(elem: ET.Element | None, tag: str) -> str | None:
    if elem is None:
        return None
    return _clean(elem.findtext(tag))


def _texts(elem: ET.Element, tag: str) -> list[str]:
    return [t for t in (_clean(e.text) for e in elem.findall(tag)) if t]


def normalize_date(value: str | None) -> str | None:
    """'2025. 05. 09.' / '20001205' / '2025-05-09' → '2025-05-09'. 해석 불가면 원문."""
    if not value:
        return None
    digits = re.findall(r"\d+", value)
    if len(digits) >= 3 and len(digits[0]) == 4:
        y, m, d = digits[0], digits[1].zfill(2), digits[2].zfill(2)
        return f"{y}-{m}-{d}"
    if len(digits) == 1 and len(digits[0]) == 8:
        s = digits[0]
        return f"{s[:4]}-{s[4:6]}-{s[6:]}"
    return value


def _parse_root(xml_text: str) -> ET.Element:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        snippet = xml_text.strip()[:200]
        raise ParseError(f"XML 파싱 실패: {e} / 응답 앞부분: {snippet!r}") from e

    # 게이트웨이 오류 응답: <OpenAPI_ServiceResponse><cmmMsgHeader>...</cmmMsgHeader>
    if root.tag == "OpenAPI_ServiceResponse" or root.find(".//cmmMsgHeader") is not None:
        hdr = root.find(".//cmmMsgHeader")
        auth = _text(hdr, "returnAuthMsg") or ""
        err = _text(hdr, "errMsg") or ""
        code = _text(hdr, "returnReasonCode")
        msg = " / ".join(x for x in (err, auth) if x) or "알 수 없는 게이트웨이 오류"
        fatal = any(m in auth for m in _FATAL_MARKERS)
        raise ApiGatewayError(f"data.go.kr 오류: {msg} (code={code})", code, fatal=fatal)
    return root


def _result_message(root: ET.Element) -> str | None:
    code = _clean(root.findtext(".//result_code")) or _clean(root.findtext(".//resultCode"))
    msg = _clean(root.findtext(".//result_msg")) or _clean(root.findtext(".//resultMsg"))
    if code or msg:
        return f"{msg or ''} (code={code})".strip()
    return None


def parse_domain(xml_text: str) -> tuple[str, dict[str, Any] | None, str | None]:
    """반환: (status, data, error). status ∈ ok | not_found | error"""
    root = _parse_root(xml_text)
    kr = root.find("./whois/krdomain")
    if kr is None:
        kr = root.find(".//krdomain")
    if kr is None:
        detail = _result_message(root) or "응답에 krdomain 항목 없음"
        return "error", None, detail

    name = _text(kr, "name")
    if not name:
        # 미등록 도메인은 krdomain 이 비어서 돌아온다 (실측)
        return "not_found", None, None

    data = {
        "domain": name,
        "registrant": _text(kr, "regName"),
        "registrant_en": _text(kr, "e_regName"),
        "address": _text(kr, "addr"),
        "address_en": _text(kr, "e_addr"),
        "postcode": _text(kr, "post"),
        "admin_name": _text(kr, "adminName"),
        "admin_name_en": _text(kr, "e_adminName"),
        "admin_email": _text(kr, "adminEmail"),
        "admin_phone": _text(kr, "adminPhone"),
        "registered": normalize_date(_text(kr, "regDate")),
        "updated": normalize_date(_text(kr, "lastUpdatedDate")),
        "expires": normalize_date(_text(kr, "endDate")),
        "registrar": _text(kr, "agency"),
        "registrar_en": _text(kr, "e_agency"),
        "registrar_url": _text(kr, "agency_url"),
        "status": _texts(kr, "domainStatus"),
        "dnssec": _text(kr, "dnssec"),
        "nameservers": _texts(kr, "ns1"),
        "nameserver_ips": _texts(kr, "ip1"),
        "info_disclosed": _text(kr, "infoYN"),
    }
    return "ok", data, None


def _net_block(whois: ET.Element, lang: str, role: str) -> dict[str, Any] | None:
    base = whois.find(f"./{lang}/{role}")
    if base is None:
        return None
    net = {c.tag: _clean(c.text) for c in base.findall("./netInfo/*")}
    contact = {c.tag: _clean(c.text) for c in base.findall("./techContact/*")}
    net = {k: v for k, v in net.items() if v}
    contact = {k: v for k, v in contact.items() if v}
    if not net and not contact:
        return None
    if "regDate" in net:
        net["regDate"] = normalize_date(net["regDate"])
    if contact:
        net["contact"] = contact
    return net


def parse_ip(xml_text: str) -> tuple[str, dict[str, Any] | None, str | None]:
    root = _parse_root(xml_text)
    whois = root.find("./whois")
    if whois is None:
        whois = root.find(".//whois")
    if whois is None:
        return "error", None, _result_message(root) or "응답에 whois 항목 없음"

    data: dict[str, Any] = {
        "ip": _text(whois, "query"),
        "query_type": _text(whois, "queryType"),
        "registry": _text(whois, "registry"),
        "country": _text(whois, "countryCode"),
    }
    for role in ("ISP", "user"):
        ko = _net_block(whois, "korean", role)
        en = _net_block(whois, "english", role)
        if ko or en:
            data[role.lower()] = {"ko": ko, "en": en}

    if not any(data.get(k) for k in ("registry", "country", "isp", "user")):
        return "not_found", None, _result_message(root)
    return "ok", data, None
