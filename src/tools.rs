use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ErrorData};
use rmcp::{schemars, tool, tool_router};

use crate::client::FilescanClient;
use crate::models::*;
use crate::query::*;

/// The MCP tool router / service for Filescan.
#[derive(Clone)]
pub struct FilescanService {
    client: Arc<FilescanClient>,
}

impl FilescanService {
    pub fn new(client: FilescanClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }
}

/// Helper: serialize a response to JSON and return as a successful
/// `CallToolResult` with text content.
fn json_result<T: serde::Serialize>(value: &T) -> Result<CallToolResult, ErrorData> {
    let json_str = serde_json::to_string_pretty(value)
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![Content::text(json_str)]))
}

/// Helper: convert a `FilescanError` to an `ErrorData` for MCP.
fn to_mcp_error(err: crate::error::FilescanError) -> ErrorData {
    ErrorData::internal_error(err.mcp_message(), None)
}

// ---------------------------------------------------------------------------
// Tool Router
// ---------------------------------------------------------------------------

#[tool_router(server_handler)]
impl FilescanService {
    // ---- filescan_scan_file ----

    #[tool(
        description = "Upload a local file to Filescan.io for malware scanning. Returns a flow_id to track the scan. Required: file_path (local path to the file). Optional scan options: description, tags, password, is_private, is_private_report, skip_whitelisted, scan_engine (internal|mdcloud)."
    )]
    async fn filescan_scan_file(
        &self,
        Parameters(input): Parameters<ScanFileToolInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let file_path = &input.file_path;
        let options = input.options.as_ref();

        self.client
            .scan_file(file_path, options)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_scan_url ----

    #[tool(
        description = "Submit a URL to Filescan.io for scanning. Required: url (string). Optional scan options: description, tags, password, is_private, is_private_report, skip_whitelisted, scan_engine (internal|mdcloud). Returns flow_id for tracking."
    )]
    async fn filescan_scan_url(
        &self,
        Parameters(input): Parameters<ScanUrlToolInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = &input.url;
        let options = input.options.as_ref();

        self.client
            .scan_url(url, options)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_get_scan_reports ----

    #[tool(
        description = "Retrieve all reports for a scan flow by its flow_id. Optionally filter report fields with the 'filter' parameter (array of strings), sort with 'sorting', or request extra data with 'other'."
    )]
    async fn filescan_get_scan_reports(
        &self,
        Parameters(input): Parameters<GetScanReportsInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let query = ScanReportQuery {
            filter: input.filter,
            sorting: input.sorting,
            other: input.other,
        };

        self.client
            .scan_reports(&input.flow_id, &query)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_get_report ----

    #[tool(
        description = "Get a specific report by its report_id and file_hash. Optionally filter, sort, or request extra data."
    )]
    async fn filescan_get_report(
        &self,
        Parameters(input): Parameters<GetReportInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let query = ReportQuery {
            filter: input.filter,
            sorting: input.sorting,
            other: input.other,
        };

        self.client
            .report(&input.report_id, &input.file_hash, &query)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_search_reports ----

    #[tool(
        description = "Search Filescan reports with optional filters. Supports filtering by verdict, source_type, filetype, hashes (sha256, sha1, md5, etc.), IOCs (domain, ip, url, email), tags, date range, page/page_size, and more. Returns paginated results."
    )]
    async fn filescan_search_reports(
        &self,
        Parameters(input): Parameters<ReportSearchQuery>,
    ) -> Result<CallToolResult, ErrorData> {
        self.client
            .search_reports(&input)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_get_search_matches ----

    #[tool(
        description = "Get IOC matches for a set of report IDs. Required: report_ids (array of report ID strings). Accepts the same search filters as filescan_search_reports for additional filtering."
    )]
    async fn filescan_get_search_matches(
        &self,
        Parameters(input): Parameters<SearchMatchesInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.client
            .search_matches(input.report_ids, &input.query)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_list_public_reports ----

    #[tool(
        description = "List public reports from Filescan.io with pagination. Optional: page (default 1), page_size (5, 10, or 20; default 10)."
    )]
    async fn filescan_list_public_reports(
        &self,
        Parameters(input): Parameters<PublicReportsQuery>,
    ) -> Result<CallToolResult, ErrorData> {
        self.client
            .public_reports(&input)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }
}

// ---------------------------------------------------------------------------
// Additional MCP tool input types (not shared with models.rs)
// ---------------------------------------------------------------------------

/// Input for `filescan_get_scan_reports`.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct GetScanReportsInput {
    #[schemars(description = "Flow ID returned from scan_file or scan_url")]
    pub flow_id: String,
    #[schemars(
        description = "Optional report fields to filter (e.g. ['general', 'finalVerdict', 'allSignalGroups'])"
    )]
    #[serde(default)]
    pub filter: Option<Vec<String>>,
    #[schemars(description = "Optional sort parameters")]
    #[serde(default)]
    pub sorting: Option<Vec<String>>,
    #[schemars(description = "Optional extra data options")]
    #[serde(default)]
    pub other: Option<Vec<String>>,
}

/// Input for `filescan_get_report`.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct GetReportInput {
    #[schemars(description = "Report ID")]
    pub report_id: String,
    #[schemars(description = "SHA256 file hash")]
    pub file_hash: String,
    #[schemars(description = "Optional report fields to filter")]
    #[serde(default)]
    pub filter: Option<Vec<String>>,
    #[schemars(description = "Optional sort parameters")]
    #[serde(default)]
    pub sorting: Option<Vec<String>>,
    #[schemars(description = "Optional extra data options")]
    #[serde(default)]
    pub other: Option<Vec<String>>,
}

/// Input for `filescan_get_search_matches`.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchMatchesInput {
    #[schemars(description = "Array of report IDs to fetch matches for")]
    pub report_ids: Vec<String>,
    #[serde(flatten, default)]
    pub query: ReportSearchQuery,
}
