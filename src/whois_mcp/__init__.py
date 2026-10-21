"""Unofficial WHOIS MCP server using the KISA WHOIS API (data.go.kr)."""

__version__ = "0.2.0"


def main() -> None:
    from .server import main as _main

    _main()
