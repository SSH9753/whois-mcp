# whois-mcp

KISA whois 검색 MCP



## Install (From Source)

If you prefer to run from source or need to modify the code:

1. Clone and build:
```bash
git clone https://github.com/SSH9753/whois-mcp.git
```

2. Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "whois": {
        "command": "uv",
        "args": [
          "--directory",
          "/absolute/path/to/whois-mcp",
          "run",
          "whois-mcp"
        ],
        "env": {
            "WHOIS_SERVICE_KEY": "your_api_service_key_here"
        }
      },
  }
}
```