use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums from the OpenAPI spec
// ---------------------------------------------------------------------------

/// Scan engine selection.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanEngine {
    Internal,
    Mdcloud,
}

/// Report verdict classification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportVerdict {
    Unknown,
    Benign,
    Informational,
    #[serde(rename = "no_threat")]
    NoThreat,
    Suspicious,
    #[serde(rename = "likely_malicious")]
    LikelyMalicious,
    Malicious,
}

/// Source type of a report.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportsSourceType {
    Url,
    #[serde(rename = "url-to-file")]
    UrlToFile,
    File,
}

/// Report search method.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportSearchMethod {
    Or,
    And,
}

/// Scan flow state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Created,
    Queued,
    Scanning,
    Finished,
}

/// Main task simplified state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MainTaskSimplifiedState {
    Success,
    Failed,
    #[serde(rename = "in_progress")]
    InProgress,
}

/// Reputation IOC type for path routing – `domain`, `ip`, or `url`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReputationIocType {
    Domain,
    Ip,
    Url,
}

impl ReputationIocType {
    /// Return the snake_case string used in API path segments.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReputationIocType::Domain => "domain",
            ReputationIocType::Ip => "ip",
            ReputationIocType::Url => "url",
        }
    }
}

/// Page size for report searches — restricted to 5, 10, or 20.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "i64")]
pub struct PageSize(i64);

impl TryFrom<i64> for PageSize {
    type Error = String;

    fn try_from(n: i64) -> Result<Self, Self::Error> {
        Self::from_i64(n)
    }
}

impl PageSize {
    pub const SIZE_5: Self = PageSize(5);
    pub const SIZE_10: Self = PageSize(10);
    pub const SIZE_20: Self = PageSize(20);

    pub fn as_i64(self) -> i64 {
        self.0
    }

    /// Validate and produce a `PageSize` from an integer.
    pub fn from_i64(n: i64) -> Result<Self, String> {
        match n {
            5 => Ok(PageSize(5)),
            10 => Ok(PageSize(10)),
            20 => Ok(PageSize(20)),
            _ => Err(format!("page_size must be 5, 10, or 20, got {n}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Scan request / response models
// ---------------------------------------------------------------------------

/// Fields shared by both file-scan and URL-scan requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Optional scan configuration (shared by file and URL scans)")]
pub struct ScanOptions {
    #[schemars(description = "Description of the uploaded file or URL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[schemars(description = "Tags to associate with the scan")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,

    #[schemars(description = "If tags should be propagated to resulting reports (default true)")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagate_tags: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_private: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_private_report: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_whitelisted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_profile: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_engine: Option<ScanEngine>,
}

/// MCP tool input for `filescan_scan_file`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Upload a local file to Filescan.io for scanning")]
pub struct ScanFileToolInput {
    /// Local file path to upload.
    #[schemars(description = "Path to the local file to upload and scan")]
    pub file_path: String,

    #[serde(flatten)]
    pub options: Option<ScanOptions>,
}

/// MCP tool input for `filescan_scan_url`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Submit a URL to Filescan.io for scanning")]
pub struct ScanUrlToolInput {
    /// The URL to scan.
    #[schemars(description = "URL to submit for scanning")]
    pub url: String,

    #[serde(flatten)]
    pub options: Option<ScanOptions>,
}

/// Response from a scan initiation (both file and URL).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanResponse {
    pub flow_id: String,
    pub priority: ScanPriorityResponse,
}

/// Priority info within a scan response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanPriorityResponse {
    pub applied: i64,
    /// Note: OpenAPI schema uses the misspelled `max_posibble`.
    /// API examples suggest both `max_possible` and `max_posibble` may appear.
    #[serde(
        rename = "max_posibble",
        alias = "max_possible",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(rename = "max_possible")]
    pub max_possible: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `AllUploadRelatedReportsResponse` — response from scan-flow and specific-report
/// endpoints. The `reports` field uses `additionalProperties: true` so we
/// model it as a dynamic JSON value.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllUploadRelatedReportsResponse {
    #[serde(skip_serializing_if = "Option::is_none", alias = "flowId")]
    pub flow_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "allFinished")]
    pub all_finished: Option<bool>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "allFilesDownloadFinished"
    )]
    pub all_files_download_finished: Option<bool>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "allAdditionalStepsDone"
    )]
    pub all_additional_steps_done: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "reportsAmount")]
    pub reports_amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "pollPause")]
    pub poll_pause: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ScanState>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "scanStartedDate")]
    pub scan_started_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "positionInQueue")]
    pub position_in_queue: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "queueSize")]
    pub queue_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "fileSize")]
    pub file_size: Option<i64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "fileReadProgressBytes"
    )]
    pub file_read_progress_bytes: Option<i64>,
    /// Dynamic per-report data — OpenAPI schema uses `additionalProperties: true`.
    pub reports: serde_json::Value,
}

/// `ReportSearchResponse` — paginated search results.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReportSearchResponse {
    /// Items are variable per-report payloads; use Value for flexibility.
    pub items: Vec<serde_json::Value>,
    pub count: i64,
    #[serde(skip_serializing_if = "Option::is_none", alias = "count_search_params")]
    pub count_search_params: Option<i64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "earliest_dates_covered"
    )]
    pub earliest_dates_covered: Option<bool>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none", alias = "dbs_sync")]
    pub dbs_sync: Option<bool>,
}

// ---------------------------------------------------------------------------
// Stage 2: Availability & Reputation models
// ---------------------------------------------------------------------------

/// Response body for `POST /api/files/availability` — a dynamic map of
/// SHA256 hash → availability boolean.
///
/// Serializes as a flat JSON object: `{"hash1": true, "hash2": false}`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FileAvailabilityResponse {
    #[serde(flatten)]
    pub available: HashMap<String, bool>,
}

/// Fuzzy hash verdict used in hash reputation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FuzzyhashVerdict {
    pub hash: Option<String>,
    pub verdict: ReportVerdict,
}

/// Multi-AV scan result for **hash** reputation (`ResultMultiscan`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultMultiscan {
    pub total_av_engines: i64,
    pub detected_av_engines: i64,
    pub scan_time: String,
}

/// MDCloud lookup result for **IOC** reputation (`ResultLookup`).
/// Distinct from `ResultMultiscan` — has only `detected`, no `total_av_engines`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultLookup {
    pub scan_time: String,
    pub detected: i64,
}

/// A report summary used in reputation calculations.
///
/// `report_date` is a plain string (not a date-time) because the API
/// examples use the non-standard `MM/DD/YYYY, HH:MM:SS` format.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReportForReputationCalculation {
    pub verdict: ReportVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_date: Option<String>,
    pub report_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
}

/// Hash reputation result from `GET /api/reputation/hash` or
/// `POST /api/reputation/hash` (bulk).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReputationResultHash {
    pub sha256: String,
    pub overall_verdict: ReportVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuzzyhash: Option<FuzzyhashVerdict>,
    /// `ResultMultiscan` for hash-based reputation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdcloud: Option<ResultMultiscan>,
    pub filescan_reports: Vec<ReportForReputationCalculation>,
}

/// IOC reputation result from `GET /api/reputation/{ioc_type}` or
/// `POST /api/reputation/{ioc_type}` (bulk).
///
/// The `ioc_type` field is a plain string in API responses (not the enum),
/// matching the OpenAPI schema.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReputationResultIoc {
    pub ioc_type: String,
    pub ioc_value: String,
    pub overall_verdict: ReportVerdict,
    /// `ResultLookup` for IOC-based reputation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdcloud: Option<ResultLookup>,
    pub filescan_reports: Vec<ReportForReputationCalculation>,
}

// ---------------------------------------------------------------------------
// Tagged MCP tool response wrappers for stable single-vs-bulk output
// ---------------------------------------------------------------------------

/// Wraps hash reputation output so MCP tools always return a tagged
/// `{ "mode": "single", "result": {...} }` or `{ "mode": "bulk", "results": [...] }`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode")]
pub enum HashReputationResponse {
    #[serde(rename = "single")]
    Single { result: ReputationResultHash },
    #[serde(rename = "bulk")]
    Bulk { results: Vec<ReputationResultHash> },
}

/// Wraps IOC reputation output with the same tagged shape.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode")]
pub enum IocReputationResponse {
    #[serde(rename = "single")]
    Single { result: ReputationResultIoc },
    #[serde(rename = "bulk")]
    Bulk { results: Vec<ReputationResultIoc> },
}

/// Body for `POST /api/reports/search/matches`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(description = "Request body: list of report IDs to fetch matches for")]
pub struct MatchesPayload {
    #[serde(rename = "reports_ids")]
    #[schemars(description = "Array of report IDs to fetch IOC matches for")]
    pub report_ids: Vec<String>,
}

/// A single match-origin entry within a `MatchesResponseItem`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatchesOrigin {
    pub origin: MatchesOriginData,
    /// Dynamic match details.
    pub matches: serde_json::Value,
}

/// Origin data for a match.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatchesOriginData {
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filetype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub relation: String,
}

/// A single item in the search-matches response array.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatchesResponseItem {
    pub report_id: String,
    pub matches: Vec<MatchesOrigin>,
}

// ---------------------------------------------------------------------------
// Stage 3: Threat Intel & Similarity models
// ---------------------------------------------------------------------------

/// File name and hash within a prevalence/similars report.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IocPrevalenceReportFile {
    pub name: String,
    pub sha256: String,
}

/// Report item in a prevalence response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IocPrevalenceReport {
    pub flow_id: String,
    pub report_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<IocPrevalenceReportFile>,
    pub verdict: ReportVerdict,
    pub created_date: String,
}

/// Prevalence response for a single IOC value.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IocsPrevalenceResponse {
    /// Counts by verdict (keys are snake_case ReportVerdict values).
    pub counts: HashMap<String, i64>,
    pub reports: Vec<IocPrevalenceReport>,
    pub verdict: ReportVerdict,
}

/// Type alias for the triple-nested prevalence/similars response map.
pub type IocsPrevalenceMap = HashMap<String, HashMap<String, IocsPrevalenceResponse>>;

/// Request body for `POST /api/threatintel/get-prevalence`.
///
/// `exclude_report_ids` is a **query** parameter, not part of this body.
/// It is handled separately by the client method.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IocsPrevalenceSearchParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_save_id: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imphash: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentihash: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuzzyfsiohash: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unc_path: Option<Vec<String>>,
    /// Look-back window in days (1–30, default 30).
    #[serde(default = "default_prevalence_days")]
    pub days: i64,
}

fn default_prevalence_days() -> i64 {
    30
}

impl Default for IocsPrevalenceSearchParams {
    fn default() -> Self {
        Self {
            domain: None,
            ip: None,
            url: None,
            uuid: None,
            email: None,
            registry_path: None,
            revision_save_id: None,
            sha1: None,
            sha256: None,
            sha512: None,
            md5: None,
            imphash: None,
            ssdeep: None,
            authentihash: None,
            fuzzyfsiohash: None,
            unc_path: None,
            days: 30,
        }
    }
}

/// Breakdown of similarity scores by category.
///
/// All fields are optional — the API returns only a subset.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SimilaritiesResultSimilarity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_indicators: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sections: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_techniques: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_metadata: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub characteristic: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly_sections: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dotnet_info: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_info: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb_guid: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_header_compiler_ids: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apk: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub biffopcodes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emulation: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extendeddata: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segments: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_parse: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_ocr: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_internal: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings_input_file: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggeredconsumerids: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vba_emulation: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yara: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_ids: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certifications: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weighted_numerics: Option<f64>,
}

/// File details for a similarity search result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DetailsResultSimilarity {
    pub start_date: String,
    pub file_size: f64,
    pub tags: Vec<String>,
    pub verdict: ReportVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_dotnet: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

/// One similarity entry within a similarity search response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultSimilarity {
    pub sha256: String,
    pub overall_similarity: f64,
    pub similarities: SimilaritiesResultSimilarity,
    pub details: DetailsResultSimilarity,
}

/// Response for `GET /api/similarity-search/similarity`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SimilaritiesResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub most_similar: Vec<ResultSimilarity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub most_recent: Vec<ResultSimilarity>,
}

// ---------------------------------------------------------------------------
// serde tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_response_accepts_max_posibble() {
        let json = r#"{"flow_id":"abc123","priority":{"applied":100,"max_posibble":100}}"#;
        let resp: ScanResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.priority.max_possible, Some(100));
    }

    #[test]
    fn scan_response_accepts_max_possible_alias() {
        let json = r#"{"flow_id":"abc123","priority":{"applied":100,"max_possible":100}}"#;
        let resp: ScanResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.priority.max_possible, Some(100));
    }

    #[test]
    fn scan_response_accepts_missing_priority_limit() {
        let json = r#"{"flow_id":"abc123","priority":{"applied":100}}"#;
        let resp: ScanResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.priority.applied, 100);
        assert_eq!(resp.priority.max_possible, None);
    }

    #[test]
    fn page_size_serializes_as_int() {
        let ps = PageSize::SIZE_10;
        let json = serde_json::to_string(&ps).unwrap();
        assert_eq!(json, "10");
    }

    #[test]
    fn all_upload_reports_response_parses_basic() {
        let json = r#"{
            "flowId": "f123",
            "allFinished": true,
            "reports": {"r1": {"finalVerdict": {"verdict": "MALICIOUS"}}}
        }"#;
        let r: AllUploadRelatedReportsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.flow_id.unwrap(), "f123");
        assert!(r.all_finished.unwrap());
    }

    #[test]
    fn matches_payload_serializes() {
        let payload = MatchesPayload {
            report_ids: vec!["id1".into(), "id2".into()],
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("reports_ids"));
        assert!(json.contains("id1"));
    }

    #[test]
    fn matches_response_item_parses() {
        let json = r#"{
            "report_id": "rid1",
            "matches": [
                {
                    "origin": {"sha256": "abc", "relation": "same"},
                    "matches": {"count": 5}
                }
            ]
        }"#;
        let item: MatchesResponseItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.report_id, "rid1");
        assert_eq!(item.matches.len(), 1);
        assert_eq!(item.matches[0].origin.sha256, "abc");
    }

    #[test]
    fn scan_file_tool_input_deserializes() {
        let json = r#"{"file_path":"/tmp/test.exe","description":"test"}"#;
        let input: ScanFileToolInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.file_path, "/tmp/test.exe");
        assert_eq!(input.options.unwrap().description.unwrap(), "test");
    }

    // -----------------------------------------------------------------------
    // Stage 2 model serde tests
    // -----------------------------------------------------------------------

    #[test]
    fn reputation_ioc_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ReputationIocType::Domain).unwrap(),
            r#""domain""#
        );
        assert_eq!(
            serde_json::to_string(&ReputationIocType::Ip).unwrap(),
            r#""ip""#
        );
        assert_eq!(
            serde_json::to_string(&ReputationIocType::Url).unwrap(),
            r#""url""#
        );
    }

    #[test]
    fn reputation_ioc_type_deserializes() {
        let d: ReputationIocType = serde_json::from_str(r#""domain""#).unwrap();
        assert!(matches!(d, ReputationIocType::Domain));
        let i: ReputationIocType = serde_json::from_str(r#""ip""#).unwrap();
        assert!(matches!(i, ReputationIocType::Ip));
        let u: ReputationIocType = serde_json::from_str(r#""url""#).unwrap();
        assert!(matches!(u, ReputationIocType::Url));
    }

    #[test]
    fn reputation_ioc_type_as_str() {
        assert_eq!(ReputationIocType::Domain.as_str(), "domain");
        assert_eq!(ReputationIocType::Ip.as_str(), "ip");
        assert_eq!(ReputationIocType::Url.as_str(), "url");
    }

    #[test]
    fn file_availability_response_parses() {
        let json = r#"{"abc123":true,"def456":false}"#;
        let r: FileAvailabilityResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.available.len(), 2);
        assert_eq!(r.available.get("abc123"), Some(&true));
        assert_eq!(r.available.get("def456"), Some(&false));
    }

    #[test]
    fn file_availability_response_empty() {
        let json = r#"{}"#;
        let r: FileAvailabilityResponse = serde_json::from_str(json).unwrap();
        assert!(r.available.is_empty());
    }

    #[test]
    fn fuzzyhash_verdict_parses_with_hash() {
        let json = r#"{"hash":"abc123","verdict":"malicious"}"#;
        let f: FuzzyhashVerdict = serde_json::from_str(json).unwrap();
        assert_eq!(f.hash.unwrap(), "abc123");
        assert!(matches!(f.verdict, ReportVerdict::Malicious));
    }

    #[test]
    fn fuzzyhash_verdict_parses_without_hash() {
        let json = r#"{"verdict":"unknown"}"#;
        let f: FuzzyhashVerdict = serde_json::from_str(json).unwrap();
        assert!(f.hash.is_none());
    }

    #[test]
    fn result_multiscan_parses() {
        let json = r#"{"total_av_engines":19,"detected_av_engines":3,"scan_time":"2024-09-27T15:44:17.884000"}"#;
        let r: ResultMultiscan = serde_json::from_str(json).unwrap();
        assert_eq!(r.total_av_engines, 19);
        assert_eq!(r.detected_av_engines, 3);
    }

    #[test]
    fn result_lookup_parses() {
        let json = r#"{"scan_time":"2025-02-10T13:29:04.035000","detected":0}"#;
        let r: ResultLookup = serde_json::from_str(json).unwrap();
        assert_eq!(r.detected, 0);
    }

    #[test]
    fn report_for_reputation_calculation_parses() {
        let json = r#"{"verdict":"malicious","report_date":"01/28/2025, 10:24:45","report_id":"d2e899de","flow_id":"6798b06a"}"#;
        let r: ReportForReputationCalculation = serde_json::from_str(json).unwrap();
        assert_eq!(r.report_id, "d2e899de");
        assert_eq!(r.report_date.unwrap(), "01/28/2025, 10:24:45");
        assert_eq!(r.flow_id.unwrap(), "6798b06a");
        assert!(matches!(r.verdict, ReportVerdict::Malicious));
    }

    #[test]
    fn report_for_reputation_missing_optionals() {
        let json = r#"{"verdict":"benign","report_id":"r1"}"#;
        let r: ReportForReputationCalculation = serde_json::from_str(json).unwrap();
        assert!(r.report_date.is_none());
        assert!(r.flow_id.is_none());
    }

    #[test]
    fn reputation_result_hash_parses_full() {
        let json = r#"{
            "sha256":"cd75828da7199ec27875ebb93c9bb848fe5c58baea4de185af37dc3731cb9ffc",
            "overall_verdict":"malicious",
            "fuzzyhash":{"hash":"dfccbab156d3685c12ce4c9250850ef20b09f4f9c16a343cbee8b7314ea314a0","verdict":"unknown"},
            "mdcloud":{"total_av_engines":19,"detected_av_engines":0,"scan_time":"2023-02-01T19:01:17.707000"},
            "filescan_reports":[{"verdict":"malicious","report_date":"01/28/2025, 10:24:45","report_id":"d2e899de","flow_id":"6798b06a"}]
        }"#;
        let r: ReputationResultHash = serde_json::from_str(json).unwrap();
        assert_eq!(r.sha256.len(), 64);
        assert!(r.mdcloud.is_some());
        assert_eq!(r.filescan_reports.len(), 1);
    }

    #[test]
    fn reputation_result_hash_parses_minimal() {
        let json = r#"{
            "sha256":"ab12",
            "overall_verdict":"unknown",
            "filescan_reports":[]
        }"#;
        let r: ReputationResultHash = serde_json::from_str(json).unwrap();
        assert!(r.fuzzyhash.is_none());
        assert!(r.mdcloud.is_none());
        assert!(r.filescan_reports.is_empty());
    }

    #[test]
    fn reputation_result_ioc_parses() {
        let json = r#"{
            "ioc_type":"url",
            "ioc_value":"https://netflix.com",
            "overall_verdict":"malicious",
            "mdcloud":{"scan_time":"2025-02-10T13:29:04.035000","detected":0},
            "filescan_reports":[{"verdict":"malicious","report_date":"01/28/2025, 10:24:45","report_id":"r1"}]
        }"#;
        let r: ReputationResultIoc = serde_json::from_str(json).unwrap();
        assert_eq!(r.ioc_type, "url");
        assert_eq!(r.ioc_value, "https://netflix.com");
        assert!(r.mdcloud.is_some());
    }

    #[test]
    fn hash_reputation_response_single_tagged() {
        let inner = ReputationResultHash {
            sha256: "abc".into(),
            overall_verdict: ReportVerdict::Benign,
            fuzzyhash: None,
            mdcloud: None,
            filescan_reports: vec![],
        };
        let resp = HashReputationResponse::Single { result: inner };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""mode":"single""#));
        assert!(json.contains(r#""result""#));
    }

    #[test]
    fn hash_reputation_response_bulk_tagged() {
        let resp = HashReputationResponse::Bulk { results: vec![] };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""mode":"bulk""#));
        assert!(json.contains(r#""results""#));
    }

    #[test]
    fn ioc_reputation_response_single_tagged() {
        let inner = ReputationResultIoc {
            ioc_type: "domain".into(),
            ioc_value: "example.com".into(),
            overall_verdict: ReportVerdict::Unknown,
            mdcloud: None,
            filescan_reports: vec![],
        };
        let resp = IocReputationResponse::Single { result: inner };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""mode":"single""#));
        assert!(json.contains(r#""result""#));
    }

    #[test]
    fn ioc_reputation_response_bulk_tagged() {
        let resp = IocReputationResponse::Bulk { results: vec![] };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""mode":"bulk""#));
        assert!(json.contains(r#""results""#));
    }

    // -----------------------------------------------------------------------
    // Stage 3 model serde tests
    // -----------------------------------------------------------------------

    #[test]
    fn ioc_prevalence_report_file_parses() {
        let json = r#"{"name":"bad.exe","sha256":"abc123"}"#;
        let f: IocPrevalenceReportFile = serde_json::from_str(json).unwrap();
        assert_eq!(f.name, "bad.exe");
        assert_eq!(f.sha256, "abc123");
    }

    #[test]
    fn ioc_prevalence_report_parses_without_file() {
        let json = r#"{
            "flow_id":"f1",
            "report_id":"r1",
            "verdict":"malicious",
            "created_date":"2025-01-31T12:28:49"
        }"#;
        let r: IocPrevalenceReport = serde_json::from_str(json).unwrap();
        assert_eq!(r.flow_id, "f1");
        assert!(r.file.is_none());
        assert!(matches!(r.verdict, ReportVerdict::Malicious));
    }

    #[test]
    fn ioc_prevalence_report_parses_with_file() {
        let json = r#"{
            "flow_id":"f2",
            "report_id":"r2",
            "file":{"name":"test.exe","sha256":"def456"},
            "verdict":"no_threat",
            "created_date":"2025-01-28T09:21:58"
        }"#;
        let r: IocPrevalenceReport = serde_json::from_str(json).unwrap();
        let file = r.file.unwrap();
        assert_eq!(file.name, "test.exe");
        assert_eq!(file.sha256, "def456");
    }

    #[test]
    fn iocs_prevalence_response_parses() {
        let json = r#"{
            "counts":{"malicious":2,"no_threat":1},
            "reports":[
                {"flow_id":"f1","report_id":"r1","verdict":"malicious","created_date":"2025-01-31"}
            ],
            "verdict":"malicious"
        }"#;
        let r: IocsPrevalenceResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.counts.get("malicious"), Some(&2));
        assert_eq!(r.reports.len(), 1);
    }

    #[test]
    fn iocs_prevalence_map_parses_triple_nested() {
        let json = r#"{
            "ip": {
                "1.2.3.4": {
                    "counts":{"malicious":1},
                    "reports":[
                        {"flow_id":"f1","report_id":"r1","verdict":"malicious","created_date":"2025-01-31"}
                    ],
                    "verdict":"malicious"
                }
            }
        }"#;
        let m: IocsPrevalenceMap = serde_json::from_str(json).unwrap();
        assert_eq!(m.len(), 1);
        let ip_map = m.get("ip").unwrap();
        assert_eq!(ip_map.len(), 1);
        let entry = ip_map.get("1.2.3.4").unwrap();
        assert_eq!(entry.counts.get("malicious"), Some(&1));
    }

    #[test]
    fn iocs_prevalence_search_params_serializes_with_default_days() {
        let params = IocsPrevalenceSearchParams::default();
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""days":30"#));
    }

    #[test]
    fn iocs_prevalence_search_params_serializes_with_iocs() {
        let params = IocsPrevalenceSearchParams {
            sha256: Some(vec!["abc123".into()]),
            ip: Some(vec!["1.2.3.4".into()]),
            days: 7,
            ..Default::default()
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""sha256":["abc123"]"#));
        assert!(json.contains(r#""ip":["1.2.3.4"]"#));
        assert!(json.contains(r#""days":7"#));
        // Empty/None fields should be omitted
        assert!(!json.contains(r#""domain""#));
    }

    #[test]
    fn similarities_result_similarity_parses_sparse() {
        let json = r#"{"extracted":1.0,"strings":1.0,"version_info":1.0}"#;
        let s: SimilaritiesResultSimilarity = serde_json::from_str(json).unwrap();
        assert_eq!(s.extracted, Some(1.0));
        assert_eq!(s.strings, Some(1.0));
        assert_eq!(s.version_info, Some(1.0));
        assert!(s.threat_indicators.is_none());
        assert!(s.apk.is_none());
    }

    #[test]
    fn similarities_result_similarity_parses_empty() {
        let json = r#"{}"#;
        let s: SimilaritiesResultSimilarity = serde_json::from_str(json).unwrap();
        assert!(s.extracted.is_none());
        assert!(s.strings.is_none());
    }

    #[test]
    fn details_result_similarity_parses() {
        let json = r#"{
            "start_date":"2025-01-31T09:42:38",
            "file_size":3590144.0,
            "tags":["peexe","evasive"],
            "verdict":"malicious",
            "is_dotnet":0,
            "architecture":"32 Bits binary",
            "entropy":6.6975
        }"#;
        let d: DetailsResultSimilarity = serde_json::from_str(json).unwrap();
        assert_eq!(d.start_date, "2025-01-31T09:42:38");
        assert_eq!(d.file_size, 3590144.0);
        assert_eq!(d.tags.len(), 2);
        assert_eq!(d.is_dotnet, Some(0));
        assert!(d.entropy.is_some());
    }

    #[test]
    fn details_result_similarity_parses_minimal() {
        let json = r#"{
            "start_date":"2025-01-01",
            "file_size":1024.0,
            "tags":[],
            "verdict":"unknown"
        }"#;
        let d: DetailsResultSimilarity = serde_json::from_str(json).unwrap();
        assert!(d.is_dotnet.is_none());
        assert!(d.architecture.is_none());
        assert!(d.entropy.is_none());
    }

    #[test]
    fn result_similarity_parses() {
        let json = r#"{
            "sha256":"abc123",
            "overall_similarity":0.95,
            "similarities":{"extracted":1.0},
            "details":{
                "start_date":"2025-01-01",
                "file_size":1024.0,
                "tags":[],
                "verdict":"malicious"
            }
        }"#;
        let r: ResultSimilarity = serde_json::from_str(json).unwrap();
        assert_eq!(r.sha256, "abc123");
        assert_eq!(r.overall_similarity, 0.95);
        assert_eq!(r.similarities.extracted, Some(1.0));
    }

    #[test]
    fn similarities_response_parses_full() {
        let json = r#"{
            "note":"demo data",
            "most_similar":[
                {
                    "sha256":"abc123",
                    "overall_similarity":1.0,
                    "similarities":{},
                    "details":{
                        "start_date":"2025-01-01",
                        "file_size":1024.0,
                        "tags":[],
                        "verdict":"malicious"
                    }
                }
            ],
            "most_recent":[]
        }"#;
        let r: SimilaritiesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.note.unwrap(), "demo data");
        assert_eq!(r.most_similar.len(), 1);
        assert!(r.most_recent.is_empty());
    }

    #[test]
    fn similarities_response_parses_empty_arrays_and_missing_note() {
        let json = r#"{}"#;
        let r: SimilaritiesResponse = serde_json::from_str(json).unwrap();
        assert!(r.note.is_none());
        assert!(r.most_similar.is_empty());
        assert!(r.most_recent.is_empty());
    }
}
