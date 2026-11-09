"use strict";
/**
 * Hacienda Backend MCP Extension for Claude Desktop
 * Bridges MCP requests to the hacienda-backend binary.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = require("@modelcontextprotocol/sdk/server/index.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
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
            const result = (0, child_process_1.spawnSync)(candidate, ["--version"], { encoding: "utf-8" });
            if (result.status === 0) {
                return candidate;
            }
        }
        catch {
            // keep searching
        }
    }
    return "hacienda-backend";
}
const BINARY_PATH = findBinary();
const TOOLS = [
    {
        name: "search",
        description: "Hybrid search (BM25 + Vector + Lexical + RRF) over indexed documents. Returns snippets with gaze tokens (e.g., <4b31c7ee:Name_1>) - no PII exposed. Use rehydrate tool (owner-only) to recover originals.",
        inputSchema: {
            type: "object",
            properties: {
                tenant_id: { type: "string", description: "Tenant identifier (isolation key)" },
                query: { type: "string", description: "Search query" },
                top_k: { type: "number", default: 10, minimum: 1, maximum: 100 },
                rerank: { type: "boolean", default: true },
                filter: {
                    type: "object",
                    properties: {
                        connector: { type: "string" },
                        since: { type: "string", format: "date-time" },
                    },
                },
            },
            required: ["tenant_id", "query"],
        },
    },
    {
        name: "rehydrate",
        description: "Rehydrate a single gaze gateway token to its original PII value. Owner-only capability, audited.",
        inputSchema: {
            type: "object",
            properties: {
                tenant_id: { type: "string", description: "Tenant identifier" },
                entity: {
                    type: "string",
                    description: "Gaze gateway token to rehydrate (e.g., '<4b31c7ee:Name_1>')",
                },
            },
            required: ["tenant_id", "entity"],
        },
    },
    {
        name: "sync",
        description: "Trigger incremental or full index rebuild.",
        inputSchema: {
            type: "object",
            properties: {
                full: { type: "boolean", default: false },
            },
        },
    },
    {
        name: "status",
        description: "Index status: fingerprint, engine readiness, rehydration readiness.",
        inputSchema: { type: "object", properties: {} },
    },
    {
        name: "graph_entities",
        description: "Read-only Cypher query over the tenant's entity graph (GLiNER mentions + co-occurrence). Only MATCH, RETURN, WHERE, LIMIT, ORDER BY, WITH, UNION are allowed.",
        inputSchema: {
            type: "object",
            properties: {
                tenant_id: { type: "string", description: "Tenant identifier (isolation key)" },
                cypher: { type: "string", description: "Read-only Cypher query string" },
                max_rows: { type: "number", default: 200, minimum: 1, maximum: 1000 },
            },
            required: ["tenant_id", "cypher"],
        },
    },
    {
        name: "graph_rag",
        description: "GraphRAG: hybrid retrieval via entity graph expansion (vector lane + graph lane + fusion). Requires documents.embed = true.",
        inputSchema: {
            type: "object",
            properties: {
                tenant_id: { type: "string", description: "Tenant identifier (isolation key)" },
                query: { type: "string", description: "Natural language query to embed and expand" },
                hops: { type: "number", default: 2, minimum: 1, maximum: 2 },
                max_results: { type: "number", default: 50, minimum: 1, maximum: 200 },
            },
            required: ["tenant_id", "query"],
        },
    },
];
const RESOURCES = [
    {
        uri: "basemind://status",
        name: "System Status",
        description: "Current system status and health",
        mimeType: "application/json",
    },
    {
        uri: "basemind://repo/map",
        name: "Repository Map",
        description: "Repository structure and file map",
        mimeType: "application/json",
    },
];
function runBinary(args, timeoutMs) {
    const result = (0, child_process_1.spawnSync)(BINARY_PATH, args, { encoding: "utf-8", timeout: timeoutMs });
    if (result.error) {
        throw new Error(`Failed to execute hacienda-backend: ${result.error.message}`);
    }
    if (result.status !== 0) {
        throw new Error(`Command failed: ${result.stderr || result.stdout}`);
    }
    try {
        return JSON.parse(result.stdout);
    }
    catch {
        return { raw: result.stdout };
    }
}
async function main() {
    const server = new index_js_1.Server({ name: "hacienda-backend", version: "0.1.0" }, { capabilities: { tools: {}, resources: {} } });
    server.setRequestHandler(types_js_1.ListToolsRequestSchema, async () => ({ tools: TOOLS }));
    server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
        const { name } = request.params;
        const toolArgs = (request.params.arguments ?? {});
        try {
            const cmdArgs = ["mcp", "call", "--tool", name];
            for (const [key, value] of Object.entries(toolArgs)) {
                cmdArgs.push("--arg", key, JSON.stringify(value));
            }
            const result = runBinary(cmdArgs, 30000);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
        }
        catch (error) {
            return {
                content: [
                    { type: "text", text: `Error: ${error instanceof Error ? error.message : String(error)}` },
                ],
                isError: true,
            };
        }
    });
    server.setRequestHandler(types_js_1.ListResourcesRequestSchema, async () => ({ resources: RESOURCES }));
    server.setRequestHandler(types_js_1.ReadResourceRequestSchema, async (request) => {
        const { uri } = request.params;
        try {
            const result = runBinary(["mcp", "resource", "read", uri], 30000);
            return {
                contents: [{ uri, mimeType: "application/json", text: JSON.stringify(result, null, 2) }],
            };
        }
        catch (error) {
            return {
                contents: [
                    {
                        uri,
                        mimeType: "text/plain",
                        text: `Error reading resource: ${error instanceof Error ? error.message : String(error)}`,
                    },
                ],
            };
        }
    });
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("Hacienda Backend MCP server started");
}
main().catch((error) => {
    console.error("Fatal:", error);
    process.exit(1);
});
//# sourceMappingURL=index.js.map