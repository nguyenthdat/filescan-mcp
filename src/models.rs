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
    #[serde(rename = "max_posibble")]
    #[schemars(rename = "max_possible")]
    pub max_possible: i64,
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
// serde tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_response_accepts_max_posibble() {
        let json = r#"{"flow_id":"abc123","priority":{"applied":100,"max_posibble":100}}"#;
        let resp: ScanResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.priority.max_possible, 100);
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
}
