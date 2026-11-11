"use strict";
/**
 * Hacienda Backend MCP Extension for Claude Desktop.
 * Bridges the extension-facing MCP server to hacienda's MCP server transport.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = require("@modelcontextprotocol/sdk/client/index.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/client/stdio.js");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/client/streamableHttp.js");
const index_js_2 = require("@modelcontextprotocol/sdk/server/index.js");
const stdio_js_2 = require("@modelcontextprotocol/sdk/server/stdio.js");
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const child_process_1 = require("child_process");
const path_1 = require("path");
function findBinary() {
    const candidates = [
        (0, path_1.join)(process.cwd(), "target", "release", "hacienda-backend"),
        (0, path_1.join)(process.cwd(), "target", "debug", "hacienda-backend"),
        "/usr/local/bin/hacienda-backend",
        "/opt/homebrew/bin/hacienda-backend",
        "/usr/bin/hacienda-backend",
    ];
    for (const candidate of candidates) {
        try {
            const result = (0, child_process_1.spawnSync)(candidate, ["--version"], {
                encoding: "utf-8",
                stdio: ["ignore", "pipe", "pipe"],
            });
            if (result.status === 0)
                return candidate;
        }
        catch {
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
        description: "Attach a previously processed local document and return an opaque clean reference.",
        inputSchema: {
            type: "object",
            properties: { tenant_id: { type: "string" }, path: { type: "string" } },
            required: ["tenant_id", "path"],
        },
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
const RESOURCE_URIS = new Set(RESOURCES.map((resource) => resource.uri));
let backendClient;
let backendTransport;
async function getBackendClient() {
    if (backendClient)
        return backendClient;
    backendClient = new index_js_1.Client({ name: "hacienda-backend-extension", version: "0.1.0" });
    const endpoint = process.env["HACIENDA_MCP_URL"];
    backendTransport = endpoint
        ? new streamableHttp_js_1.StreamableHTTPClientTransport(new URL(endpoint))
        : new stdio_js_1.StdioClientTransport({
            command: BINARY_PATH,
            args: ["mcp", "serve", "--transport", "stdio"],
            stderr: "pipe",
        });
    await backendClient.connect(backendTransport);
    return backendClient;
}
/** Only expose fixed status codes and aggregate metadata; never backend payloads or diagnostics. */
function safeResult(result, code = "OK") {
    const value = result;
    return {
        code: value?.isError ? "E_BACKEND_TOOL" : code,
        metadata: {
            content_items: Array.isArray(value?.content) ? value.content.length : 0,
            has_structured_content: value?.structuredContent !== undefined,
        },
    };
}
async function main() {
    const server = new index_js_2.Server({ name: "hacienda-backend", version: "0.1.0" }, { capabilities: { tools: {}, resources: {} } });
    server.setRequestHandler(types_js_1.ListToolsRequestSchema, async () => ({ tools: TOOLS }));
    server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
        if (!TOOL_NAMES.has(request.params.name)) {
            return { content: [{ type: "text", text: JSON.stringify({ code: "E_TOOL_NOT_ALLOWED" }) }], isError: true };
        }
        try {
            const result = await (await getBackendClient()).callTool({
                name: request.params.name,
                arguments: request.params.arguments ?? {},
            });
            return { content: [{ type: "text", text: JSON.stringify(safeResult(result)) }] };
        }
        catch {
            return { content: [{ type: "text", text: JSON.stringify({ code: "E_TOOL_FAILED" }) }], isError: true };
        }
    });
    server.setRequestHandler(types_js_1.ListResourcesRequestSchema, async () => ({ resources: RESOURCES }));
    server.setRequestHandler(types_js_1.ReadResourceRequestSchema, async (request) => {
        const resource = RESOURCES.find(({ uri }) => uri === request.params.uri);
        if (!resource || !RESOURCE_URIS.has(resource.uri)) {
            return {
                contents: [{ uri: "hacienda://error", mimeType: "text/plain", text: "E_RESOURCE_NOT_ALLOWED" }],
                isError: true,
            };
        }
        try {
            const result = await (await getBackendClient()).readResource({ uri: resource.uri });
            const metadata = safeResult(result);
            return { contents: [{ uri: resource.uri, mimeType: "application/json", text: JSON.stringify(metadata) }] };
        }
        catch {
            return { contents: [{ uri: resource.uri, mimeType: "text/plain", text: "E_RESOURCE_FAILED" }], isError: true };
        }
    });
    await server.connect(new stdio_js_2.StdioServerTransport());
    console.error("Hacienda Backend MCP server started");
}
main().catch(() => {
    console.error("Fatal: E_SERVER_FAILED");
    process.exit(1);
});
//# sourceMappingURL=index.js.map