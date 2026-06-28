use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ErrorData};
use rmcp::{schemars, tool, tool_router};

use crate::client::FilescanClient;
use crate::models::*;
use crate::query::*;

/// Maximum items allowed in bulk reputation/availability requests (MCP safety cap).
const MAX_BULK_ITEMS: usize = 100;

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
        description = "Upload a local file to Filescan.io for malware scanning. Returns a flow_id to track the scan. Required: file_path (local path to the file). Optional scan options: description, tags, propagate_tags, password, is_private, is_private_report, skip_whitelisted, scan_engine (internal|mdcloud)."
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
        description = "Submit a URL to Filescan.io for scanning. Required: url (string). Optional scan options: description, tags, propagate_tags, password, is_private, is_private_report, skip_whitelisted, scan_engine (internal|mdcloud). Returns flow_id for tracking."
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
            .search_matches(input.report_ids, &input.query, input.unique_files)
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

    // ---- filescan_check_file_availability ----

    #[tool(
        description = "Check whether one or more files (by SHA256 hash) are already available in the Filescan system. Input: hashes (1..=100 SHA256 strings). Returns a map of hash -> boolean (true = available)."
    )]
    async fn filescan_check_file_availability(
        &self,
        Parameters(input): Parameters<CheckFileAvailabilityInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Runtime validation (MCP clients may bypass schema constraints)
        validate_bulk_list(&input.hashes, "hashes")?;

        self.client
            .check_file_availability(&input.hashes)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_get_hash_reputation ----

    #[tool(
        description = "Look up reputation for one or more SHA256 hashes. Provide exactly one of 'hash' (single → GET) or 'hashes' (bulk 1..=100 → POST). Returns a tagged response: { mode: \"single\", result } or { mode: \"bulk\", results }."
    )]
    async fn filescan_get_hash_reputation(
        &self,
        Parameters(input): Parameters<GetHashReputationInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let (is_single, sha256, hashes) = validate_hash_xor(&input)?;

        let response = if is_single {
            let result = self
                .client
                .hash_reputation_single(sha256)
                .await
                .map_err(to_mcp_error)?;
            HashReputationResponse::Single { result }
        } else {
            let results = self
                .client
                .hash_reputation_bulk(hashes)
                .await
                .map_err(to_mcp_error)?;
            HashReputationResponse::Bulk { results }
        };

        json_result(&response)
    }

    // ---- filescan_get_ioc_reputation ----

    #[tool(
        description = "Look up reputation for one or more IOCs (domain, ip, url). Required: ioc_type. Provide exactly one of 'ioc_value' (single → GET) or 'ioc_values' (bulk 1..=100 → POST). Returns a tagged response: { mode: \"single\", result } or { mode: \"bulk\", results }."
    )]
    async fn filescan_get_ioc_reputation(
        &self,
        Parameters(input): Parameters<GetIocReputationInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let ioc_type_str = input.ioc_type.as_str();
        let (is_single, value, values) = validate_ioc_xor(&input)?;

        let response = if is_single {
            let result = self
                .client
                .ioc_reputation_single(ioc_type_str, value)
                .await
                .map_err(to_mcp_error)?;
            IocReputationResponse::Single { result }
        } else {
            let results = self
                .client
                .ioc_reputation_bulk(ioc_type_str, values)
                .await
                .map_err(to_mcp_error)?;
            IocReputationResponse::Bulk { results }
        };

        json_result(&response)
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchMatchesInput {
    #[schemars(description = "Array of report IDs to fetch matches for")]
    pub report_ids: Vec<String>,
    /// If true, return only one match per unique file hash.
    #[schemars(description = "Return only one match per unique file hash (default false)")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_files: Option<bool>,
    #[serde(flatten, default)]
    pub query: ReportSearchQuery,
}

// ---------------------------------------------------------------------------
// Stage 2 MCP tool input types
// ---------------------------------------------------------------------------

/// Input for `filescan_check_file_availability`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[schemars(description = "Check whether files (by SHA256 hash) are available in Filescan")]
pub struct CheckFileAvailabilityInput {
    /// One or more SHA256 hashes to check (1..=100).
    #[schemars(length(min = 1, max = 100))]
    pub hashes: Vec<String>,
}

/// Input for `filescan_get_hash_reputation`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[schemars(description = "Look up reputation for hash(es). Provide exactly one of hash or hashes.")]
pub struct GetHashReputationInput {
    /// A single SHA256 hash (mutually exclusive with `hashes`).
    #[serde(default)]
    pub hash: Option<String>,

    /// Multiple SHA256 hashes for bulk lookup, 1..=100 (mutually exclusive with `hash`).
    #[serde(default)]
    #[schemars(length(min = 1, max = 100))]
    pub hashes: Option<Vec<String>>,
}

/// Input for `filescan_get_ioc_reputation`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[schemars(
    description = "Look up reputation for IOC(s). Provide exactly one of ioc_value or ioc_values."
)]
pub struct GetIocReputationInput {
    /// Type of IOC: domain, ip, or url.
    pub ioc_type: ReputationIocType,

    /// A single IOC value (mutually exclusive with `ioc_values`).
    #[serde(default)]
    pub ioc_value: Option<String>,

    /// Multiple IOC values for bulk lookup, 1..=100 (mutually exclusive with `ioc_value`).
    #[serde(default)]
    #[schemars(length(min = 1, max = 100))]
    pub ioc_values: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Stage 2 validation helpers
// ---------------------------------------------------------------------------

/// Runtime validation for a bulk list field (availability hashes, hash bulk, IOC bulk).
fn validate_bulk_list(items: &[String], field_name: &str) -> Result<(), ErrorData> {
    if items.is_empty() {
        return Err(ErrorData::internal_error(
            format!("Validation error: {field_name} must contain at least 1 item"),
            None,
        ));
    }
    if items.len() > MAX_BULK_ITEMS {
        return Err(ErrorData::internal_error(
            format!("Validation error: {field_name} must contain at most {MAX_BULK_ITEMS} items"),
            None,
        ));
    }
    for (i, item) in items.iter().enumerate() {
        if item.trim().is_empty() {
            return Err(ErrorData::internal_error(
                format!("Validation error: {field_name}[{i}] must not be empty"),
                None,
            ));
        }
    }
    Ok(())
}

/// XOR validation for hash reputation: exactly one of `hash` or `hashes`.
/// Returns `(is_single: bool, sha256: &str, hashes: &[String])`.
fn validate_hash_xor(input: &GetHashReputationInput) -> Result<(bool, &str, &[String]), ErrorData> {
    match (&input.hash, &input.hashes) {
        (Some(sha256), None) => {
            if sha256.trim().is_empty() {
                return Err(ErrorData::internal_error(
                    "Validation error: hash must not be empty",
                    None,
                ));
            }
            Ok((true, sha256.as_str(), &[]))
        }
        (None, Some(hashes)) => {
            validate_bulk_list(hashes, "hashes")?;
            Ok((false, "", hashes.as_slice()))
        }
        (Some(_), Some(_)) => Err(ErrorData::internal_error(
            "Validation error: provide only one of hash or hashes, not both",
            None,
        )),
        (None, None) => Err(ErrorData::internal_error(
            "Validation error: provide exactly one of hash or hashes",
            None,
        )),
    }
}

/// XOR validation for IOC reputation: exactly one of `ioc_value` or `ioc_values`.
/// Returns `(is_single: bool, value: &str, values: &[String])`.
fn validate_ioc_xor(input: &GetIocReputationInput) -> Result<(bool, &str, &[String]), ErrorData> {
    match (&input.ioc_value, &input.ioc_values) {
        (Some(value), None) => {
            if value.trim().is_empty() {
                return Err(ErrorData::internal_error(
                    "Validation error: ioc_value must not be empty",
                    None,
                ));
            }
            Ok((true, value.as_str(), &[]))
        }
        (None, Some(values)) => {
            validate_bulk_list(values, "ioc_values")?;
            Ok((false, "", values.as_slice()))
        }
        (Some(_), Some(_)) => Err(ErrorData::internal_error(
            "Validation error: provide only one of ioc_value or ioc_values, not both",
            None,
        )),
        (None, None) => Err(ErrorData::internal_error(
            "Validation error: provide exactly one of ioc_value or ioc_values",
            None,
        )),
    }
}
