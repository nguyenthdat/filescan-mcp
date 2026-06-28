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

    // ---- filescan_get_ioc_prevalence ----

    #[tool(
        description = "Get prevalence statistics for IOCs across Filescan reports. Requires at least one IOC array to be populated (e.g., sha256, md5, domain, ip, url). days must be 1..=30 (default 30). exclude_report_ids are optional report IDs to exclude from results."
    )]
    async fn filescan_get_ioc_prevalence(
        &self,
        Parameters(input): Parameters<GetIocPrevalenceInput>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_prevalence_input(&input)?;

        let body = IocsPrevalenceSearchParams {
            domain: input.domain,
            ip: input.ip,
            url: input.url,
            uuid: input.uuid,
            email: input.email,
            registry_path: input.registry_path,
            revision_save_id: input.revision_save_id,
            sha1: input.sha1,
            sha256: input.sha256,
            sha512: input.sha512,
            md5: input.md5,
            imphash: input.imphash,
            ssdeep: input.ssdeep,
            authentihash: input.authentihash,
            fuzzyfsiohash: input.fuzzyfsiohash,
            unc_path: input.unc_path,
            days: input.days,
        };

        let exclude = input.exclude_report_ids.unwrap_or_default();

        self.client
            .get_ioc_prevalence(&body, &exclude)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_get_similar_reports ----

    #[tool(
        description = "Find reports sharing the same special hashes: imphash, ssdeep, fuzzyfsiohash, or authentihash. Provide at least one hash selector. days=-1 means no time limit. exclude_report_ids are optional report IDs to exclude from results."
    )]
    async fn filescan_get_similar_reports(
        &self,
        Parameters(input): Parameters<GetSimilarReportsInput>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_similar_reports_input(&input)?;

        let query = GetSimilarReportsQuery {
            imphash: input.imphash,
            ssdeep: input.ssdeep,
            fuzzyfsiohash: input.fuzzyfsiohash,
            authentihash: input.authentihash,
            days: input.days,
            exclude_report_ids: input.exclude_report_ids,
        };

        self.client
            .get_similar_reports(&query)
            .await
            .map(|r| json_result(&r))
            .unwrap_or_else(|e| Err(to_mcp_error(e)))
    }

    // ---- filescan_similarity_search ----

    #[tool(
        description = "DEPRECATED Filescan endpoint — implemented because requested. Find similar reports by SHA256 hash, tags, minimum similarity threshold (0..=100), and/or verdict. Returns top 10 most similar and top 10 most recent findings."
    )]
    async fn filescan_similarity_search(
        &self,
        Parameters(input): Parameters<SimilaritySearchInput>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_similarity_search_input(&input)?;

        let query = SimilaritySearchQuery {
            hash: input.hash,
            min_similarity: input.min_similarity,
            verdict: input.verdict,
            tags: input.tags,
        };

        self.client
            .similarity_search(&query)
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

// ---------------------------------------------------------------------------
// Stage 3 MCP tool input types
// ---------------------------------------------------------------------------

/// Input for `filescan_get_ioc_prevalence`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[schemars(description = "Get prevalence statistics for IOCs across Filescan reports")]
pub struct GetIocPrevalenceInput {
    #[serde(default)]
    #[schemars(description = "List of SHA256 hashes to check prevalence for")]
    pub sha256: Option<Vec<String>>,
    #[serde(default)]
    pub md5: Option<Vec<String>>,
    #[serde(default)]
    pub sha1: Option<Vec<String>>,
    #[serde(default)]
    pub sha512: Option<Vec<String>>,
    #[serde(default)]
    #[schemars(description = "Domain names to check prevalence for")]
    pub domain: Option<Vec<String>>,
    #[serde(default)]
    #[schemars(description = "IP addresses to check prevalence for")]
    pub ip: Option<Vec<String>>,
    #[serde(default)]
    #[schemars(description = "URLs to check prevalence for")]
    pub url: Option<Vec<String>>,
    #[serde(default)]
    pub uuid: Option<Vec<String>>,
    #[serde(default)]
    pub email: Option<Vec<String>>,
    #[serde(default)]
    pub registry_path: Option<Vec<String>>,
    #[serde(default)]
    pub revision_save_id: Option<Vec<String>>,
    #[serde(default)]
    pub imphash: Option<Vec<String>>,
    #[serde(default)]
    pub ssdeep: Option<Vec<String>>,
    #[serde(default)]
    pub authentihash: Option<Vec<String>>,
    #[serde(default)]
    pub fuzzyfsiohash: Option<Vec<String>>,
    #[serde(default)]
    pub unc_path: Option<Vec<String>>,
    /// Look-back window in days (1–30, default 30).
    #[serde(default = "default_prevalence_days")]
    #[schemars(range(min = 1, max = 30))]
    pub days: i64,
    /// Report IDs to exclude from results.
    #[serde(default)]
    pub exclude_report_ids: Option<Vec<String>>,
}

fn default_prevalence_days() -> i64 {
    30
}

impl Default for GetIocPrevalenceInput {
    fn default() -> Self {
        Self {
            sha256: None,
            md5: None,
            sha1: None,
            sha512: None,
            domain: None,
            ip: None,
            url: None,
            uuid: None,
            email: None,
            registry_path: None,
            revision_save_id: None,
            imphash: None,
            ssdeep: None,
            authentihash: None,
            fuzzyfsiohash: None,
            unc_path: None,
            days: 30,
            exclude_report_ids: None,
        }
    }
}

/// Input for `filescan_get_similar_reports`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[schemars(
    description = "Find reports with the same special hashes (imphash, ssdeep, fuzzyfsiohash, authentihash)"
)]
pub struct GetSimilarReportsInput {
    #[serde(default)]
    #[schemars(description = "Import hash to search for")]
    pub imphash: Option<String>,
    #[serde(default)]
    #[schemars(description = "SSDEEP fuzzy hash to search for")]
    pub ssdeep: Option<String>,
    #[serde(default)]
    #[schemars(description = "Fuzzy FSIO hash to search for")]
    pub fuzzyfsiohash: Option<String>,
    #[serde(default)]
    #[schemars(description = "Authentihash to search for")]
    pub authentihash: Option<String>,
    /// Age limit in days (-1 = no limit, default).
    #[serde(default = "default_similar_days_tool")]
    pub days: i64,
    /// Report IDs to exclude from results.
    #[serde(default)]
    pub exclude_report_ids: Option<Vec<String>>,
}

fn default_similar_days_tool() -> i64 {
    -1
}

impl Default for GetSimilarReportsInput {
    fn default() -> Self {
        Self {
            imphash: None,
            ssdeep: None,
            fuzzyfsiohash: None,
            authentihash: None,
            days: -1,
            exclude_report_ids: None,
        }
    }
}

/// Input for `filescan_similarity_search`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[schemars(
    description = "DEPRECATED. Find similar reports based on SHA256 hash, tags, threshold, and verdict"
)]
pub struct SimilaritySearchInput {
    #[serde(default)]
    #[schemars(description = "SHA256 hash to find similar reports for")]
    pub hash: Option<String>,
    /// Minimum similarity threshold (0–100, default 0).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100))]
    pub min_similarity: Option<i64>,
    /// Filter by verdict.
    #[serde(default)]
    pub verdict: Option<ReportVerdict>,
    /// Filter by tags (repeated query params).
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Stage 3 validation helpers
// ---------------------------------------------------------------------------

/// Validate a list field with the same rules as `validate_bulk_list` but
/// tolerant of `None`. Returns `Ok(true)` if the list is non-empty after
/// validation.
fn validate_optional_list(
    items: &Option<Vec<String>>,
    field_name: &str,
) -> Result<bool, ErrorData> {
    match items {
        None => Ok(false),
        Some(list) => {
            validate_bulk_list(list, field_name)?;
            Ok(!list.is_empty())
        }
    }
}

/// Validate prevalence input: at least one IOC array populated, days 1..=30,
/// list caps enforced.
fn validate_prevalence_input(input: &GetIocPrevalenceInput) -> Result<(), ErrorData> {
    // days bounds
    if input.days < 1 || input.days > 30 {
        return Err(ErrorData::internal_error(
            "Validation error: days must be between 1 and 30",
            None,
        ));
    }

    // At least one IOC array must be non-empty
    let ioc_lists: [(&str, &Option<Vec<String>>); 16] = [
        ("domain", &input.domain),
        ("ip", &input.ip),
        ("url", &input.url),
        ("uuid", &input.uuid),
        ("email", &input.email),
        ("registry_path", &input.registry_path),
        ("revision_save_id", &input.revision_save_id),
        ("sha1", &input.sha1),
        ("sha256", &input.sha256),
        ("sha512", &input.sha512),
        ("md5", &input.md5),
        ("imphash", &input.imphash),
        ("ssdeep", &input.ssdeep),
        ("authentihash", &input.authentihash),
        ("fuzzyfsiohash", &input.fuzzyfsiohash),
        ("unc_path", &input.unc_path),
    ];

    let mut any_populated = false;
    for (name, list) in &ioc_lists {
        let populated = validate_optional_list(list, name)?;
        any_populated = any_populated || populated;
    }

    if !any_populated {
        return Err(ErrorData::internal_error(
            "Validation error: provide at least one IOC value (domain, ip, url, uuid, email, registry_path, revision_save_id, sha1, sha256, sha512, md5, imphash, ssdeep, authentihash, fuzzyfsiohash, or unc_path)",
            None,
        ));
    }

    // Optional exclude_report_ids
    if let Some(ref ids) = input.exclude_report_ids {
        validate_bulk_list(ids, "exclude_report_ids")?;
    }

    Ok(())
}

/// Validate similar reports input: at least one hash selector, days not
/// 0 or below -1, list caps enforced.
fn validate_similar_reports_input(input: &GetSimilarReportsInput) -> Result<(), ErrorData> {
    // days must be -1 or positive
    if input.days < -1 || input.days == 0 {
        return Err(ErrorData::internal_error(
            "Validation error: days must be -1 or a positive integer",
            None,
        ));
    }

    // At least one hash selector non-empty
    let hashes: [(&str, &Option<String>); 4] = [
        ("imphash", &input.imphash),
        ("ssdeep", &input.ssdeep),
        ("fuzzyfsiohash", &input.fuzzyfsiohash),
        ("authentihash", &input.authentihash),
    ];

    let mut any_provided = false;
    for (name, val) in &hashes {
        if let Some(v) = val {
            if v.trim().is_empty() {
                return Err(ErrorData::internal_error(
                    format!("Validation error: {name} must not be empty"),
                    None,
                ));
            }
            any_provided = true;
        }
    }

    if !any_provided {
        return Err(ErrorData::internal_error(
            "Validation error: provide at least one of imphash, ssdeep, fuzzyfsiohash, or authentihash",
            None,
        ));
    }

    // Optional exclude_report_ids
    if let Some(ref ids) = input.exclude_report_ids {
        validate_bulk_list(ids, "exclude_report_ids")?;
    }

    Ok(())
}

/// Validate similarity search input: at least one selector, min_similarity
/// 0..=100 if present, hash not empty, tags validated.
fn validate_similarity_search_input(input: &SimilaritySearchInput) -> Result<(), ErrorData> {
    // min_similarity bounds
    if let Some(ms) = input.min_similarity
        && !(0..=100).contains(&ms) {
            return Err(ErrorData::internal_error(
                "Validation error: min_similarity must be between 0 and 100",
                None,
            ));
        }

    // hash non-empty if provided
    if let Some(ref h) = input.hash
        && h.trim().is_empty() {
            return Err(ErrorData::internal_error(
                "Validation error: hash must not be empty",
                None,
            ));
        }

    // tags validated if present
    if let Some(ref tags) = input.tags {
        validate_bulk_list(tags, "tags")?;
    }

    // At least one selector
    let any_selector = input.hash.is_some()
        || input.min_similarity.is_some()
        || input.verdict.is_some()
        || input.tags.as_ref().is_some_and(|t| !t.is_empty());

    if !any_selector {
        return Err(ErrorData::internal_error(
            "Validation error: provide at least one similarity selector (hash, tags, verdict, or min_similarity)",
            None,
        ));
    }

    Ok(())
}
