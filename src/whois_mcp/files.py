"""입력 파일 읽기, 결과 저장(CSV/JSONL), 요약 통계."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .client import WhoisResult

# ---------------------------------------------------------------- 입력 ---- #


def resolve_path(path: str) -> Path:
    return Path(path).expanduser().resolve()


def read_query_file(path: Path, limit: int) -> tuple[list[str], bool]:
    """한 줄에 하나씩. '#' 주석·빈 줄 무시. CSV/TSV 면 첫 번째 열만 사용.
    반환: (항목들, limit 초과로 잘렸는지)"""
    if not path.is_file():
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {path}")

    raw = path.read_bytes()
    for enc in ("utf-8-sig", "cp949"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")

    items: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        first = s.replace("\t", ",").split(",", 1)[0].strip()
        if first:
            items.append(first)
        if len(items) > limit:
            return items[:limit], True
    return items, False


def default_output_path(input_path: Path, fmt: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return input_path.with_name(f"{input_path.stem}_whois_{stamp}.{fmt}")


# ---------------------------------------------------------------- 출력 ---- #

DOMAIN_COLUMNS = [
    "registrant", "registrant_en", "registrar", "registered", "updated", "expires",
    "domain_status", "nameservers", "nameserver_ips", "dnssec",
    "admin_name", "admin_email", "admin_phone", "address", "postcode", "info_disclosed",
]
IP_COLUMNS = [
    "registry", "country", "isp_org", "isp_org_en", "isp_service", "isp_range", "isp_prefix",
    "isp_regdate", "isp_contact_email", "user_org", "user_org_en", "user_range", "user_contact_email",
]
BASE_COLUMNS = ["input", "query", "kind", "status", "error", "queried_at"]
ALL_COLUMNS = BASE_COLUMNS + DOMAIN_COLUMNS + IP_COLUMNS


def _join(v: Any) -> Any:
    return "; ".join(map(str, v)) if isinstance(v, list) else v


def _net(data: dict[str, Any], role: str, lang: str) -> dict[str, Any]:
    block = (data.get(role) or {}).get(lang) or {}
    return block


def flatten(r: WhoisResult) -> dict[str, Any]:
    row: dict[str, Any] = {k: getattr(r, k) for k in BASE_COLUMNS}
    d = r.data or {}
    if r.kind == "domain":
        for k in DOMAIN_COLUMNS:
            row[k] = _join(d.get("status" if k == "domain_status" else k))
    elif r.kind == "ip":
        isp_ko, isp_en = _net(d, "isp", "ko"), _net(d, "isp", "en")
        usr_ko, usr_en = _net(d, "user", "ko"), _net(d, "user", "en")
        row.update(
            registry=d.get("registry"),
            country=d.get("country"),
            isp_org=isp_ko.get("orgName"),
            isp_org_en=isp_en.get("orgName"),
            isp_service=isp_ko.get("servName") or isp_en.get("servName"),
            isp_range=isp_ko.get("range") or isp_en.get("range"),
            isp_prefix=isp_ko.get("prefix") or isp_en.get("prefix"),
            isp_regdate=isp_ko.get("regDate") or isp_en.get("regDate"),
            isp_contact_email=(isp_ko.get("contact") or isp_en.get("contact") or {}).get("email"),
            user_org=usr_ko.get("orgName"),
            user_org_en=usr_en.get("orgName"),
            user_range=usr_ko.get("range") or usr_en.get("range"),
            user_contact_email=(usr_ko.get("contact") or usr_en.get("contact") or {}).get("email"),
        )
    return row


def write_results(results: Iterable[WhoisResult], path: Path, fmt: str) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    if fmt == "jsonl":
        with path.open("w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")
                n += 1
    else:
        # utf-8-sig: 엑셀에서 한글이 깨지지 않도록 BOM 포함
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=ALL_COLUMNS, extrasaction="ignore")
            w.writeheader()
            for r in results:
                w.writerow(flatten(r))
                n += 1
    return n


# ---------------------------------------------------------------- 요약 ---- #


def _parse_iso(s: str | None) -> date | None:
    try:
        return date.fromisoformat(s) if s else None
    except ValueError:
        return None


def summarize(results: list[WhoisResult], *, recent_days: int = 30, top: int = 10) -> dict[str, Any]:
    status = Counter(r.status for r in results)
    kinds = Counter(r.kind for r in results)

    registrars: Counter[str] = Counter()
    registrants: Counter[str] = Counter()
    isps: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    recent: list[dict[str, Any]] = []
    cutoff = date.today() - timedelta(days=recent_days)

    for r in results:
        if r.status != "ok" or not r.data:
            continue
        d = r.data
        if r.kind == "domain":
            if d.get("registrar"):
                registrars[d["registrar"]] += 1
            if d.get("registrant"):
                registrants[d["registrant"]] += 1
            reg = _parse_iso(d.get("registered"))
            if reg and reg >= cutoff:
                recent.append({"domain": r.query, "registered": d["registered"], "registrar": d.get("registrar")})
        elif r.kind == "ip":
            org = _net(d, "isp", "ko").get("orgName") or _net(d, "isp", "en").get("orgName")
            if org:
                isps[org] += 1
            if d.get("country"):
                countries[d["country"]] += 1

    errors = Counter(r.error for r in results if r.status == "error" and r.error)
    recent.sort(key=lambda x: x["registered"], reverse=True)
    return {
        "total": len(results),
        "by_status": dict(status),
        "by_kind": dict(kinds),
        "top_registrars": registrars.most_common(top),
        "top_registrants": registrants.most_common(top),
        "top_isps": isps.most_common(top),
        "countries": countries.most_common(top),
        f"registered_within_{recent_days}d": {"count": len(recent), "items": recent[:20]},
        "top_errors": errors.most_common(5),
    }
