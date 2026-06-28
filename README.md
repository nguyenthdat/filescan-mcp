# Filescan MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server written in Rust that exposes [Filescan.io](https://www.filescan.io) API endpoints as MCP tools.

## Tools

| Tool | Endpoint | Description |
|---|---|---|
| `filescan_scan_file` | `POST /api/scan/file` | Upload a local file for malware scanning |
| `filescan_scan_url` | `POST /api/scan/url` | Submit a URL for scanning |
| `filescan_get_scan_reports` | `GET /api/scan/{flow_id}/report` | Retrieve reports for a scan flow |
| `filescan_get_report` | `GET /api/reports/{report_id}/{file_hash}` | Get a specific report |
| `filescan_search_reports` | `GET /api/reports/search` | Search reports with many filters |
| `filescan_get_search_matches` | `POST /api/reports/search/matches` | Get IOC matches for report IDs |
| `filescan_list_public_reports` | `GET /api/reports` | List public reports |
| `filescan_check_file_availability` | `POST /api/files/availability` | Check if file hashes are available in Filescan |
| `filescan_get_hash_reputation` | `GET/POST /api/reputation/hash` | Look up reputation for SHA256 hashes (single or bulk) |
| `filescan_get_ioc_reputation` | `GET/POST /api/reputation/{ioc_type}` | Look up reputation for IOCs — domain/ip/url (single or bulk) |

### Stage 2 Tool Notes

- `filescan_get_hash_reputation`: Provide exactly one of `hash` (single → GET) or `hashes` (bulk → POST, 1–100 items).
- `filescan_get_ioc_reputation`: Provide exactly one of `ioc_value` (single → GET) or `ioc_values` (bulk → POST, 1–100 items). `ioc_type` must be `domain`, `ip`, or `url`.
- Bulk lookups are capped at 100 items for safety; this is an MCP convention, not an API limit.
- Reputation results use tagged output: `{ "mode": "single", "result": {...} }` or `{ "mode": "bulk", "results": [...] }`.

## Setup

### Prerequisites

- Rust 1.80+ (stable)
- A [Filescan.io](https://www.filescan.io) API key

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FILESCAN_API_KEY` | **Yes** | — | Your Filescan.io API key |
| `FILESCAN_BASE_URL` | No | `https://www.filescan.io` | Base URL for the Filescan API |
| `FILESCAN_TIMEOUT_SECS` | No | `60` | HTTP request timeout in seconds |

### Build and Run

```bash
cargo build --release
```

The binary is at `target/release/filescan-mcp`. Run with:

```bash
export FILESCAN_API_KEY="your-api-key-here"
./target/release/filescan-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filescan": {
      "command": "/path/to/target/release/filescan-mcp",
      "env": {
        "FILESCAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Development

```bash
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
```

## Coverage Notes (MVP)

### Implemented

- All 7 Phase 1 tools are implemented exactly per the OpenAPI analysis.
- Stage 2 tools: `filescan_check_file_availability`, `filescan_get_hash_reputation`, `filescan_get_ioc_reputation` — all 3 implemented.
- Typed input structs with `schemars` JSON schemas for MCP tool registration.
- Typed `ScanResponse`, `ScanPriorityResponse`, `AllUploadRelatedReportsResponse`, `ReportSearchResponse`, `MatchesResponseItem` models.
- Stage 2 models: `ReputationResultHash`, `ReputationResultIoc`, `FuzzyhashVerdict`, `ResultMultiscan`, `ResultLookup`, `ReportForReputationCalculation`, `FileAvailabilityResponse`.
- Tagged response wrappers (`HashReputationResponse`, `IocReputationResponse`) for stable single-vs-bulk output.
- All 39 report search query parameters supported.
- `ReportSearchQuery` shared between search and matches endpoints.
- Multipart file upload with local file path validation.
- URL-encoded form submission for URL scan.
- Error handling for 400/401/403/404/413/415/422/429 with actionable messages.
- `Retry-After` header handling for 429 rate limiting.
- XOR input validation for reputation tools (exactly one of single or bulk must be provided).
- Bulk request safety cap (100 items max) with runtime enforcement.
- API key redaction in `Debug` output and logs.

### Intentionally Deferred

- Stage 3 tools: `filescan_get_ioc_prevalence`, `filescan_get_similar_reports`, `filescan_similarity_search`.
- Stage 4 metadata tools: `filescan_system_info`, `filescan_system_version`, `filescan_system_config`, etc.
- Admin/mutation endpoints (news create/delete).
- UI endpoints (logo, translations, languages, countries, etc.).

### Caveats

- The `max_posibble` typo in `ScanPriorityResponse` is handled with `#[serde(rename)]`. The schema also displays as `max_possible`.
- For `POST /api/reports/search/matches`, `unique_files` is exposed as an optional query parameter alongside `reports_ids` and the shared search query filters.
- Large response payloads (report bodies) use `serde_json::Value` rather than fully-typed structs — this is intentional to handle the `additionalProperties: true` schema.
- `propagate_tags` defaults to `true` in the OpenAPI spec but is not sent if unset — let the API handle the default.
- The `scan_file` tool uses `file_path` (local path), not base64 content. This is the MCP stdio convention.
