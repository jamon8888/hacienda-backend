//! Closed-manifest and no-raw contract tests for MCP-facing artifacts.

use std::collections::HashSet;

use hacienda_backend::{Capability, McpServer, Principal, ToolRegistry};
use serde_json::Value;

const EXPECTED_TOOLS: &[&str] = &[
    "search",
    "sync",
    "status",
    "attach_local_doc",
    "graph_entities",
    "graph_rag",
];

const EXPECTED_RESOURCES: &[&str] = &["basemind://status", "basemind://repo/map"];

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn names(value: &Value, field: &str) -> Vec<String> {
    value["mcp"][field]
        .as_array()
        .unwrap_or_else(|| panic!("mcp.{field} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .or_else(|| entry.get("name").and_then(Value::as_str).map(str::to_owned))
                .or_else(|| entry.get("uri").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| panic!("mcp.{field} entry has no name/uri"))
        })
        .collect()
}

#[tokio::test]
async fn rust_stdio_manifest_is_closed_and_has_no_raw_tool() {
    let principal = Principal {
        id: "contract-test".into(),
        name: "contract-test".into(),
        capabilities: vec![
            Capability::Search,
            Capability::Sync,
            Capability::Status,
            Capability::AttachLocalDoc,
            Capability::GraphRag,
        ],
        tenant_ids: HashSet::from([String::from("tenant")]),
    };
    let server = McpServer::new(hacienda_backend::DefaultResolver::new());
    let tools = server.advertised_tools(&principal).await;
    let actual: HashSet<_> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    let expected: HashSet<_> = EXPECTED_TOOLS.iter().copied().collect();

    assert_eq!(actual, expected);
    assert!(!actual.contains("rehydrate"));
    assert!(!actual.contains("vault"));
    assert!(tools.iter().all(|tool| {
        !tool
            .description
            .as_deref()
            .unwrap_or_default()
            .contains("rehydrat")
    }));
}

#[test]
fn extension_manifests_enumerate_only_token_safe_tools_and_resources() {
    let package: Value = serde_json::from_str(&read("mcp-extension/package.json")).unwrap();
    let mpcb: Value = serde_json::from_str(&read("mcp-extension/hacienda-backend.mpcb")).unwrap();

    assert_eq!(
        names(&package, "tools"),
        EXPECTED_TOOLS
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        names(&package, "resources"),
        EXPECTED_RESOURCES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        names(&mpcb, "tools"),
        EXPECTED_TOOLS
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        names(&mpcb, "resources"),
        EXPECTED_RESOURCES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    );

    for path in [
        "mcp-extension/src/index.ts",
        "mcp-extension/dist/index.js",
        "mcp-extension/package.json",
        "mcp-extension/hacienda-backend.mpcb",
    ] {
        let artifact = read(path);
        assert!(
            !artifact.contains("\"name\": \"rehydrate\""),
            "raw tool in {path}"
        );
        assert!(
            !artifact.contains("\"vault\""),
            "broad vault surface in {path}"
        );
        assert!(
            !artifact.contains("SEEDED_VAULT_VALUE"),
            "seeded value in {path}"
        );
    }

    let source = read("mcp-extension/src/index.ts");
    assert!(source.contains("E_TOOL_NOT_ALLOWED"));
    assert!(source.contains("E_RESOURCE_NOT_ALLOWED"));
    assert!(source.contains("content_items"));
    assert!(source.contains("has_structured_content"));
}

#[test]
fn registry_rejects_unadvertised_raw_name_before_dispatch() {
    let registry = ToolRegistry::new();
    assert!(!registry.contains("rehydrate"));
    assert!(!registry.contains("vault"));
}
