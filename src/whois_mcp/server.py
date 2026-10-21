"""KISA 후이즈 API를 사용하는 비공식 WHOIS MCP 서버 (MCP Python SDK v2)."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .client import FatalApiError, WhoisApiClient, MissingServiceKey
from .config import Settings
from .files import default_output_path, read_query_file, resolve_path, summarize, write_results
from .normalize import dedupe, normalize

# stdio 전송에서 stdout 은 JSON-RPC 통로이므로 로그는 반드시 stderr 로.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("whois_mcp")


@dataclass
class AppState:
    settings: Settings
    client: WhoisApiClient


def _make_client(settings: Settings) -> WhoisApiClient:
    """테스트에서 모의 transport 를 주입할 수 있도록 분리."""
    return WhoisApiClient(settings)


@asynccontextmanager
async def lifespan(_server: MCPServer) -> AsyncIterator[AppState]:
    settings = Settings.from_env()
    if not settings.service_key:
        log.warning("WHOIS_SERVICE_KEY 미설정 — 조회 도구 호출 시 오류를 반환합니다.")
    async with _make_client(settings) as client:
        yield AppState(settings, client)


mcp = MCPServer(
    "kr-whois",
    version=__version__,
    instructions=(
        "KISA(한국인터넷진흥원) 후이즈 API로 국가도메인(.kr/.한국)과 IP 주소의 등록정보를 조회한다. "
        "1~수십 건은 whois_lookup / whois_bulk_lookup, 수백 건 이상이나 파일 목록은 "
        "whois_preview_file로 먼저 건수를 확인한 뒤 whois_bulk_lookup_file로 서버 측에서 처리하라. "
        "입력의 디팽(hxxp, [.]), URL 형태는 자동 정규화된다. .kr 이 아닌 도메인은 조회하지 않고 skipped 처리된다."
    ),
    lifespan=lifespan,
)

_LOOKUP = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=True)


def _state(ctx: Context) -> AppState:
    return ctx.request_context.lifespan_context  # type: ignore[no-any-return]


def _require_key(state: AppState) -> None:
    if not state.settings.service_key:
        raise ToolError(
            "WHOIS_SERVICE_KEY 가 설정되지 않았습니다. 공공데이터포털(data.go.kr)에서 "
            "'한국인터넷진흥원_후이즈 검색 서비스' 활용신청 후 받은 인증키를 MCP 설정 env 에 넣어주세요."
        )


@mcp.tool(
    title="WHOIS 단건 조회",
    annotations=_LOOKUP,
)
async def whois_lookup(query: str, ctx: Context) -> dict[str, Any]:
    """국가도메인(.kr/.한국) 또는 IP 주소 하나의 WHOIS 정보를 조회한다.

    Args:
        query: 도메인, IP, 또는 URL. 디팽 표기(hxxps://example[.]kr)도 허용.

    Returns:
        status(ok/not_found/skipped/invalid/error)와 data. 도메인은 등록인·등록대행자·등록/만료일·네임서버,
        IP는 할당기관(registry)·국가·ISP/사용자 기관 정보.
    """
    state = _state(ctx)
    _require_key(state)
    try:
        r = await state.client.lookup(query)
    except (FatalApiError, MissingServiceKey) as e:
        raise ToolError(str(e)) from e
    return r.to_dict()


@mcp.tool(
    title="WHOIS 다건 조회",
    annotations=_LOOKUP,
)
async def whois_bulk_lookup(queries: list[str], ctx: Context) -> dict[str, Any]:
    """도메인/IP 여러 개를 한 번에 조회한다 (기본 최대 100건). 그 이상은 whois_bulk_lookup_file 을 쓴다.

    Args:
        queries: 도메인/IP/URL 목록. 중복은 자동 제거된다.
    """
    state = _state(ctx)
    _require_key(state)
    limit = state.settings.max_inline_items
    if len(queries) > limit:
        raise ToolError(
            f"{len(queries)}건은 인라인 한도({limit}건)를 넘습니다. 목록을 파일로 저장한 뒤 whois_bulk_lookup_file 을 사용하세요."
        )

    normalized, dup = dedupe([normalize(q) for q in queries])
    total = len(normalized)

    async def progress(done: int, _r: Any) -> None:
        await ctx.report_progress(done, total)

    results, aborted = await state.client.lookup_many(normalized, on_result=progress)
    return {
        "summary": summarize(results),
        "duplicates_removed": dup,
        "aborted": aborted,
        "results": [r.to_dict() for r in results],
    }


@mcp.tool(
    title="조회 대상 파일 미리보기",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
)
async def whois_preview_file(input_path: str, ctx: Context) -> dict[str, Any]:
    """API를 호출하지 않고 목록 파일을 분석한다: 총 건수, 도메인/IP/제외/오류 건수, 중복 수, 샘플.
    대량 조회 전에 일일 트래픽 소모량을 가늠하는 용도.

    Args:
        input_path: 한 줄에 하나씩 적힌 txt/csv 파일 경로 (CSV는 첫 열 사용, '#'은 주석).
    """
    state = _state(ctx)
    path = resolve_path(input_path)
    try:
        raw, truncated = read_query_file(path, state.settings.max_file_items)
    except FileNotFoundError as e:
        raise ToolError(str(e)) from e

    normalized, dup = dedupe([normalize(x) for x in raw])
    by_kind: dict[str, int] = {}
    samples: dict[str, list[dict[str, str | None]]] = {}
    for q in normalized:
        by_kind[q.kind] = by_kind.get(q.kind, 0) + 1
        bucket = samples.setdefault(q.kind, [])
        if len(bucket) < 5:
            bucket.append({"input": q.raw, "query": q.value, "reason": q.reason})

    return {
        "file": str(path),
        "lines_read": len(raw),
        "truncated_at_limit": state.settings.max_file_items if truncated else None,
        "duplicates_removed": dup,
        "by_kind": by_kind,
        "api_calls_needed": by_kind.get("domain", 0) + by_kind.get("ip", 0),
        "samples": samples,
    }


@mcp.tool(
    title="WHOIS 파일 대량 조회",
    annotations=ToolAnnotations(
        read_only_hint=False,  # 결과 파일을 새로 쓴다
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
async def whois_bulk_lookup_file(
    input_path: str,
    ctx: Context,
    output_path: str | None = None,
    output_format: Literal["csv", "jsonl"] = "csv",
    recent_days: int = 30,
) -> dict[str, Any]:
    """목록 파일 전체를 서버 측에서 조회하고 결과를 파일로 저장한다. 결과 본문은 대화로 돌려보내지 않고
    요약 통계(상태별 건수, 상위 등록대행자/ISP, 최근 N일 내 신규 등록 도메인 등)만 반환한다.

    Args:
        input_path: 조회할 목록 파일 경로 (txt/csv).
        output_path: 결과 파일 경로. 생략 시 입력 파일 옆에 '<이름>_whois_<시각>.<형식>' 으로 저장.
        output_format: csv(엑셀용, UTF-8 BOM) 또는 jsonl(원본 구조 보존).
        recent_days: 이 일수 이내에 등록된 도메인을 '신규 등록'으로 따로 집계 (피싱 의심 선별용).
    """
    state = _state(ctx)
    _require_key(state)
    in_path = resolve_path(input_path)
    try:
        raw, truncated = read_query_file(in_path, state.settings.max_file_items)
    except FileNotFoundError as e:
        raise ToolError(str(e)) from e
    if not raw:
        raise ToolError("파일에 조회할 항목이 없습니다.")

    out_path = resolve_path(output_path) if output_path else default_output_path(in_path, output_format)
    if out_path == in_path:
        raise ToolError("출력 경로가 입력 파일과 같습니다.")

    normalized, dup = dedupe([normalize(x) for x in raw])
    total = len(normalized)
    step = max(1, total // 100)
    log.info("%d건 조회 시작 (중복 %d건 제거, 동시 %d)", total, dup, state.settings.concurrency)

    async def progress(done: int, _r: Any) -> None:
        if done % step == 0 or done == total:
            await ctx.report_progress(done, total, f"{done}/{total}")

    results, aborted = await state.client.lookup_many(normalized, on_result=progress)
    saved = write_results(results, out_path, output_format)

    return {
        "output_file": str(out_path),
        "records_saved": saved,
        "duplicates_removed": dup,
        "truncated_at_limit": state.settings.max_file_items if truncated else None,
        "aborted": aborted,
        "summary": summarize(results, recent_days=recent_days),
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="whois-mcp", description="Unofficial WHOIS MCP server using the KISA WHOIS API")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    log.info("whois-mcp %s 시작 (transport=%s)", __version__, args.transport)
    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
