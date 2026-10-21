"""환경변수 기반 설정."""

from __future__ import annotations

import os
from dataclasses import dataclass

# 공공데이터포털(data.go.kr) KISA 후이즈 검색 서비스 기본 엔드포인트.
# https 지원 여부가 확인되면 WHOIS_API_BASE 로 바꿔 쓸 수 있다.
DEFAULT_API_BASE = "http://apis.data.go.kr/B551505/whois"


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _float_env(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    service_key: str | None
    api_base: str = DEFAULT_API_BASE
    timeout: float = 10.0
    concurrency: int = 5
    max_retries: int = 2
    max_file_items: int = 50_000
    max_inline_items: int = 100

    @classmethod
    def from_env(cls) -> "Settings":
        key = (os.getenv("WHOIS_SERVICE_KEY") or "").strip()
        if key in ("", "your_api_service_key_here", "your_service_key_here"):
            key = None
        return cls(
            service_key=key,
            api_base=(os.getenv("WHOIS_API_BASE") or DEFAULT_API_BASE).rstrip("/"),
            timeout=_float_env("WHOIS_TIMEOUT", 10.0, 1.0),
            concurrency=_int_env("WHOIS_CONCURRENCY", 5),
            max_retries=_int_env("WHOIS_MAX_RETRIES", 2, 0),
            max_file_items=_int_env("WHOIS_MAX_FILE_ITEMS", 50_000),
            max_inline_items=_int_env("WHOIS_MAX_INLINE_ITEMS", 100),
        )
