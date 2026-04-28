# Purple AI MCP Server

Fork of [Sentinel-One/purple-mcp](https://github.com/Sentinel-One/purple-mcp) with added support for storing the API token in the OS credential store (Windows Credential Manager) instead of plaintext configuration files.

## What is Purple AI MCP?

Purple AI MCP is a [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI clients (Claude Desktop, Cursor, etc.) to SentinelOne's security platform. It gives AI assistants direct access to:

- **Purple AI** — natural language queries against your security data
- **Singularity Data Lake** — run and retrieve SDL queries
- **Alerts** — list, search, and inspect security alerts
- **Vulnerabilities** — query vulnerability findings
- **Misconfigurations** — review cloud and Kubernetes misconfigurations
- **Asset Inventory** — search and explore your asset inventory

Purple AI MCP is read-only — it cannot make changes to your SentinelOne account.

## Quick Start

### Install uv

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## Requirements

- [uv](https://docs.astral.sh/uv/) installed
- A SentinelOne Console API token with **Account** or **Site** level permissions (not Global)
- Your SentinelOne console base URL (e.g. `https://usea1-008.sentinelone.net`)

## 1. Store your token in Windows Credential Manager

Run this once in PowerShell:

```powershell
cmdkey /generic:"purple-mcp" /user:"PURPLEMCP_CONSOLE_TOKEN" /pass:"your-token-here"
```

To verify:

```powershell
cmdkey /list:"purple-mcp"
```

To remove:

```powershell
cmdkey /delete:"purple-mcp"
```

## 2. Configure Claude Desktop

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "purple-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "purple-mcp @ https://github.com/wojtekkura/purple-mcp/archive/refs/heads/main.tar.gz",
        "purple-mcp",
        "--mode",
        "stdio"
      ],
      "env": {
        "PURPLEMCP_CONSOLE_BASE_URL": "https://your-console.sentinelone.net"
      }
    }
  }
}
```

Replace `https://your-console.sentinelone.net` with your actual console URL. The token is read automatically from Windows Credential Manager at startup — no token in the config file.

Restart Claude Desktop after saving the file.

## License

MIT — see [LICENSE](LICENSE)
