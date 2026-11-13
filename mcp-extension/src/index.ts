/**
 * Hacienda Backend MCP Extension for Claude Desktop.
 * Bridges the extension-facing MCP server to hacienda's MCP server transport.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { spawnSync } from "child_process";
import { join } from "path";

function findBinary(): string {
  const candidates = [
    join(process.cwd(), "target", "release", "hacienda-backend"),
    join(process.cwd(), "target", "debug", "hacienda-backend"),
    "/usr/local/bin/hacienda-backend",
    "/opt/homebrew/bin/hacienda-backend",
    "/usr/bin/hacienda-backend",
  ];
  for (const candidate of candidates) {
    try {
      const result = spawnSync(candidate, ["--version"], {
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      if (result.status === 0) return candidate;
    } catch {
      // Keep searching without exposing subprocess diagnostics.
    }
  }
  return "hacienda-backend";
}

const BINARY_PATH = findBinary();

const TOOLS = [
  {
    name: "search",
    description: "Search indexed documents; returns tokenized snippets and metadata only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: { type: "string" },
        query: { type: "string" },
        top_k: { type: "number", default: 10, minimum: 1, maximum: 100 },
        rerank: { type: "boolean", default: true },
        filter: { type: "object" },
      },
      required: ["tenant_id", "query"],
    },
  },
  {
    name: "sync",
    description: "Trigger an incremental or full index rebuild.",
    inputSchema: { type: "object", properties: { full: { type: "boolean", default: false } } },
  },
  {
    name: "status",
    description: "Return index and engine status metadata.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "attach_local_doc",
    description: "Attach a local document through the backend disclosure policy.",
    inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  },
  {
    name: "request_human_disclosure",
    description: "Request human approval for a disclosure operation.",
    inputSchema: { type: "object", properties: { request_id: { type: "string" } }, required: ["request_id"] },
  },
  {
    name: "disclosure_status",
    description: "Return disclosure approval status metadata.",
    inputSchema: { type: "object", properties: { request_id: { type: "string" } } },
  },
  {
    name: "graph_entities",
    description: "Read-only entity graph query; returns tokenized metadata only.",
    inputSchema: { type: "object", properties: { tenant_id: { type: "string" }, cypher: { type: "string" }, max_rows: { type: "number" } }, required: ["tenant_id", "cypher"] },
  },
  {
    name: "graph_rag",
    description: "GraphRAG retrieval; returns tokenized snippets and metadata only.",
    inputSchema: { type: "object", properties: { tenant_id: { type: "string" }, query: { type: "string" }, hops: { type: "number" }, max_results: { type: "number" } }, required: ["tenant_id", "query"] },
  },
];

const TOOL_NAMES = new Set(TOOLS.map((tool) => tool.name));

const RESOURCES = [
  { uri: "basemind://status", name: "System Status", description: "Status metadata", mimeType: "application/json" },
  { uri: "basemind://repo/map", name: "Repository Map", description: "Repository metadata", mimeType: "application/json" },
];

let backendClient: Client | undefined;
let backendTransport: StdioClientTransport | StreamableHTTPClientTransport | undefined;

async function getBackendClient(): Promise<Client> {
  if (backendClient) return backendClient;
  backendClient = new Client({ name: "hacienda-backend-extension", version: "0.1.0" });
  const endpoint = process.env["HACIENDA_MCP_URL"];
  backendTransport = endpoint
    ? new StreamableHTTPClientTransport(new URL(endpoint))
    : new StdioClientTransport({
        command: BINARY_PATH,
        args: ["mcp", "serve", "--transport", "stdio"],
        stderr: "pipe",
      });
  await backendClient.connect(backendTransport);
  return backendClient;
}

/** Only expose fixed status codes and aggregate metadata; never backend payloads or diagnostics. */
function safeResult(result: unknown, code = "OK"): Record<string, unknown> {
  const value = result as { content?: unknown[]; isError?: boolean; structuredContent?: unknown } | null;
  return {
    code: value?.isError ? "E_BACKEND_TOOL" : code,
    metadata: {
      content_items: Array.isArray(value?.content) ? value.content.length : 0,
      has_structured_content: value?.structuredContent !== undefined,
    },
  };
}

async function main(): Promise<void> {
  const server = new Server(
    { name: "hacienda-backend", version: "0.1.0" },
    { capabilities: { tools: {}, resources: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (!TOOL_NAMES.has(request.params.name)) {
      return { content: [{ type: "text", text: JSON.stringify({ code: "E_TOOL_NOT_ALLOWED" }) }], isError: true };
    }
    try {
      const result = await (await getBackendClient()).callTool({
        name: request.params.name,
        arguments: request.params.arguments ?? {},
      });
      return { content: [{ type: "text", text: JSON.stringify(safeResult(result)) }] };
    } catch {
      return { content: [{ type: "text", text: JSON.stringify({ code: "E_TOOL_FAILED" }) }], isError: true };
    }
  });

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: RESOURCES }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    try {
      const result = await (await getBackendClient()).readResource({ uri: request.params.uri });
      const metadata = safeResult(result);
      return { contents: [{ uri: request.params.uri, mimeType: "application/json", text: JSON.stringify(metadata) }] };
    } catch {
      return { contents: [{ uri: request.params.uri, mimeType: "text/plain", text: "E_RESOURCE_FAILED" }] };
    }
  });

  await server.connect(new StdioServerTransport());
  console.error("Hacienda Backend MCP server started");
}

main().catch(() => {
  console.error("Fatal: E_SERVER_FAILED");
  process.exit(1);
});
