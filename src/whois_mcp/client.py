"""KISA 후이즈 API 비동기 클라이언트."""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Literal

import httpx

from .config import Settings
from .normalize import NormalizedQuery, normalize
from .parsers import ApiGatewayError, ParseError, parse_domain, parse_ip

log = logging.getLogger(__name__)

Status = Literal["ok", "not_found", "skipped", "invalid", "error"]


@dataclass
class WhoisResult:
    input: str
    query: str
    kind: str
    status: Status
    data: dict[str, Any] | None = None
    error: str | None = None
    queried_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


class MissingServiceKey(Exception):
    pass


class FatalApiError(Exception):
    """인증키 오류·트래픽 초과처럼 계속해도 의미 없는 오류."""


class _Stopped(Exception):
    """대량 조회 중 다른 작업에서 치명적 오류가 나 요청을 보내지 않음."""


_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class WhoisApiClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self._sem = asyncio.Semaphore(settings.concurrency)
        self._http = httpx.AsyncClient(
            timeout=settings.timeout,
            transport=transport,
            headers={"User-Agent": "whois-mcp"},
            limits=httpx.Limits(max_connections=settings.concurrency * 2),
        )

    async def __aenter__(self) -> "WhoisApiClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ #
    async def _request(self, endpoint: str, query: str, stop: asyncio.Event | None = None) -> str:
        if not self.settings.service_key:
            raise MissingServiceKey("WHOIS_SERVICE_KEY 환경변수가 설정되지 않았습니다.")
        url = f"{self.settings.api_base}/{endpoint}"
        params = {"serviceKey": self.settings.service_key, "query": query, "answer": "xml"}

        last_exc: Exception | None = None
        for attempt in range(self.settings.max_retries + 1):
            try:
                async with self._sem:
                    if stop is not None and stop.is_set():
                        raise _Stopped
                    resp = await self._http.get(url, params=params)
                if resp.status_code in _RETRYABLE_STATUS:
                    last_exc = RuntimeError(f"HTTP {resp.status_code}")
                elif resp.status_code != 200:
                    raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]!r}")
                else:
                    return resp.text
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last_exc = e
            if attempt < self.settings.max_retries:
                await asyncio.sleep(0.5 * 2**attempt + random.random() * 0.2)
        raise RuntimeError(f"요청 실패({self.settings.max_retries + 1}회 시도): {type(last_exc).__name__}: {last_exc}")

    async def lookup_normalized(self, q: NormalizedQuery, stop: asyncio.Event | None = None) -> WhoisResult:
        if q.kind in ("invalid", "skipped"):
            return WhoisResult(q.raw, q.value, q.kind, q.kind, error=q.reason)  # type: ignore[arg-type]

        endpoint, parser = ("ip_address", parse_ip) if q.kind == "ip" else ("domain_name", parse_domain)
        try:
            text = await self._request(endpoint, q.value, stop)
            status, data, err = parser(text)
            return WhoisResult(q.raw, q.value, q.kind, status, data, err)  # type: ignore[arg-type]
        except ApiGatewayError as e:
            if e.fatal:
                raise FatalApiError(str(e)) from e
            return WhoisResult(q.raw, q.value, q.kind, "error", error=str(e))
        except MissingServiceKey:
            raise
        except (ParseError, RuntimeError) as e:
            return WhoisResult(q.raw, q.value, q.kind, "error", error=str(e))

    async def lookup(self, raw: str, *, kr_only: bool = True) -> WhoisResult:
        return await self.lookup_normalized(normalize(raw, kr_only=kr_only))

    async def lookup_many(
        self,
        queries: Iterable[NormalizedQuery],
        on_result: Callable[[int, WhoisResult], Awaitable[None] | None] | None = None,
    ) -> tuple[list[WhoisResult], str | None]:
        """동시성 제한 하에 조회. 치명적 오류가 나면 남은 요청을 보내지 않고 (부분결과, 사유)를 반환."""
        items = list(queries)
        results: list[WhoisResult | None] = [None] * len(items)
        abort_reason: str | None = None
        stop = asyncio.Event()
        done = 0

        async def run(i: int, q: NormalizedQuery) -> None:
            nonlocal done, abort_reason
            try:
                r = await self.lookup_normalized(q, stop)
            except (FatalApiError, MissingServiceKey) as e:
                if not stop.is_set():
                    abort_reason = str(e)
                    stop.set()
                return
            except _Stopped:
                return
            results[i] = r
            done += 1
            if on_result is not None:
                maybe = on_result(done, r)
                if asyncio.iscoroutine(maybe):
                    await maybe

        # 치명적 오류가 나면 stop 이벤트가 켜지고, 아직 요청을 보내지 않은 작업은 API 를 호출하지 않는다.
        await asyncio.gather(*(run(i, q) for i, q in enumerate(items)))

        final = [
            r if r is not None else WhoisResult(q.raw, q.value, q.kind, "error", error=f"중단됨: {abort_reason}")
            for r, q in zip(results, items)
        ]
        return final, abort_reason
