"""입력값 정규화: 디팽(defang) 복원, URL→호스트 추출, IP/도메인 판별."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

Kind = Literal["domain", "ip", "invalid", "skipped"]

# KISA 후이즈는 국가도메인(.kr, .한국)만 다룬다. xn--3e0b707e 는 '.한국'의 퓨니코드.
KR_SUFFIXES = (".kr", ".한국", ".xn--3e0b707e")

# .kr 의 2단계 도메인(Public Suffix List 'kr' 섹션 기준). 이 아래에 등록된 이름은 3단계가 등록 단위다.
# KISA 후이즈 API는 서브도메인(www.kisa.or.kr)을 'code=031 질의 내용 부정확'으로 거부하므로(실측)
# 등록 도메인 단위로 잘라서 조회한다.
KR_SLDS = frozenset(
    """ac ai co es go hs io it kg me mil ms ne or pe re sc
    busan chungbuk chungnam daegu daejeon gangwon gwangju gyeongbuk gyeonggi
    gyeongnam incheon jeju jeonbuk jeonnam seoul ulsan""".split()
)

_DEFANG = [
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"^hxxps", re.I), "https"),
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^fxp", re.I), "ftp"),
]
_LABEL = re.compile(r"^(?!-)[a-z0-9\-ㄱ-ㆎ가-힣]{1,63}(?<!-)$", re.I)


@dataclass(frozen=True)
class NormalizedQuery:
    raw: str
    value: str
    kind: Kind
    reason: str | None = None


def refang(text: str) -> str:
    s = text.strip().strip("\"'")
    for pattern, repl in _DEFANG:
        s = pattern.sub(repl, s)
    return s


def _extract_host(s: str) -> str:
    if "://" in s:
        host = urlsplit(s).hostname or ""
        return host
    # 스킴 없는 'example.kr/path', 'example.kr:8080'
    host = re.split(r"[/?#]", s, maxsplit=1)[0]
    if host.startswith("[") and "]" in host:  # [IPv6]:port
        return host[1 : host.index("]")]
    if host.count(":") == 1:  # host:port (IPv6 는 콜론이 여러 개)
        host = host.split(":", 1)[0]
    return host


def normalize(raw: str, *, kr_only: bool = True) -> NormalizedQuery:
    s = refang(raw)
    if not s:
        return NormalizedQuery(raw, s, "invalid", "빈 값")

    if re.match(r"^[\d.:a-f]+/\d{1,3}$", s, re.I):
        return NormalizedQuery(raw, s, "invalid", "CIDR 대역은 지원하지 않음 (대표 IP로 조회)")

    host = _extract_host(s).strip().rstrip(".").lower()
    if not host:
        return NormalizedQuery(raw, s, "invalid", "호스트를 추출할 수 없음")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        value = str(ip)
        if not ip.is_global:
            return NormalizedQuery(raw, value, "skipped", "사설/예약 IP 대역")
        return NormalizedQuery(raw, value, "ip")

    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels):
        return NormalizedQuery(raw, host, "invalid", "도메인/IP 형식 아님")

    if kr_only and not host.endswith(KR_SUFFIXES):
        return NormalizedQuery(raw, host, "skipped", "국가도메인(.kr/.한국) 아님 — KISA 후이즈 조회 대상 외")

    labels_kr = host.split(".")
    if labels_kr[-1] == "kr" and len(labels_kr) == 2 and labels_kr[0] in KR_SLDS:
        return NormalizedQuery(raw, host, "invalid", "2단계 도메인 자체(co.kr 등)는 조회 대상 아님")

    return NormalizedQuery(raw, registered_domain(host), "domain")


def registered_domain(host: str) -> str:
    """www.login.example.co.kr → example.co.kr, sub.example.kr → example.kr, a.b.한국 → b.한국"""
    labels = host.split(".")
    if labels[-1] == "kr" and len(labels) >= 3 and labels[-2] in KR_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def dedupe(items: list[NormalizedQuery]) -> tuple[list[NormalizedQuery], int]:
    """조회 대상(domain/ip)은 value 기준으로 중복 제거. 나머지는 그대로 둔다."""
    seen: set[tuple[str, str]] = set()
    out: list[NormalizedQuery] = []
    dup = 0
    for q in items:
        if q.kind in ("domain", "ip"):
            k = (q.kind, q.value)
            if k in seen:
                dup += 1
                continue
            seen.add(k)
        out.append(q)
    return out, dup
