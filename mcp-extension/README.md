# Hacienda Backend MCP Extension for Claude Desktop

This extension provides a closed-manifest MCP integration for the hacienda-backend binary. It exposes tokenized search, index controls, opaque processed-document references, and optional graph retrieval.

> This extension exposes tokenized snippets and metadata only. It does not provide raw rehydration or a recovery path.

## Installation

### Option 1: Install from npm (recommended)

```bash
npm install -g hacienda-backend
```

Then add to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "hacienda-backend": {
      "command": "npx",
      "args": ["hacienda-backend", "mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

### Option 2: Install .mpcb extension (Claude Desktop)

1. Download `hacienda-backend.mpcb` from the [releases](https://github.com/jamon8888/hacienda-backend/releases)
2. Double-click the `.mpcb` file to install in Claude Desktop
3. Restart Claude Desktop

### Option 3: From source

```bash
git clone https://github.com/jamon8888/hacienda-backend
cd hacienda-backend/mcp-extension
npm install
npm run build
```

Then add to Claude Desktop config:

```json
{
  "mcpServers": {
    "hacienda-backend": {
      "command": "node",
      "args": ["/path/to/hacienda-backend/mcp-extension/dist/index.js"]
    }
  }
}
```

## Requirements

- **Node.js** >= 20.0.0
- **hacienda-backend binary** - must be in PATH or installed via `cargo install hacienda-backend`
- **Claude Desktop** >= 0.8.0

## Available Tools

| Tool | Description |
|------|-------------|
| `search` | Hybrid search (BM25 + Vector + Lexical + RRF) over indexed documents |
| `sync` | Trigger incremental or full index rebuild |
| `status` | Index status and engine readiness metadata |
| `attach_local_doc` | Attach a previously processed local document and return an opaque clean reference |
| `graph_entities` | Read-only Cypher query over the entity graph |
| `graph_rag` | GraphRAG: hybrid retrieval via entity graph expansion |

## Resources

- `basemind://status` - System status metadata
- `basemind://repo/map` - Repository metadata

Resource reads return status codes and metadata only; the extension never rehydrates raw content.

## Transport

The extension connects to the backend using the MCP client SDK. By default it starts:

```bash
hacienda-backend mcp serve --transport stdio
```

For a configured Streamable HTTP endpoint, set `HACIENDA_MCP_URL` in the extension environment. The extension uses that endpoint instead of spawning a subprocess.

## Configuration

The extension looks for the `hacienda-backend` binary in these locations (in order):

1. `./target/release/hacienda-backend` (relative to extension)
2. `./target/debug/hacienda-backend` (relative to extension)
3. `/usr/local/bin/hacienda-backend`
3. `/opt/homebrew/bin/hacienda-backend`
3. `/usr/bin/hacienda-backend`
4. From PATH (`hacienda-backend`)

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev
```

## Publishing

```bash
# Update version
npm version patch|minor|major

# Build
npm run build

# Publish to npm
npm publish --access public
```

## License

MIT License - see LICENSE file for details.
