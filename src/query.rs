use crate::models::{
    MainTaskSimplifiedState, PageSize, ReportSearchMethod, ReportVerdict, ReportsSourceType,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Full set of search query parameters for `GET /api/reports/search` and
/// `POST /api/reports/search/matches`.
///
/// All fields are optional. Array-type fields use a comma-separated string;
/// the OpenAPI spec accepts repeated query params for arrays.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ReportSearchQuery {
    /// Search reports with a max age in days (-1 = no limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<i64>,

    /// Page number (1-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,

    /// Page size: 5, 10, or 20.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<PageSize>,

    /// Search method: `or` or `and`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<ReportSearchMethod>,

    /// Include derived files (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_files: Option<bool>,

    /// Remove date-related search limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_date_limit: Option<bool>,

    /// Free-text query string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,

    /// Filter by verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,

    /// Source type filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<ReportsSourceType>,

    /// File type filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filetype: Option<String>,

    /// Single tag filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Multi-tag filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,

    /// Start date (ISO date string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_from: Option<String>,

    /// End date (ISO date string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_to: Option<String>,

    /// Minimum detection rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_from: Option<i64>,

    /// Maximum detection rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_to: Option<i64>,

    // IOC filters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_save_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yara_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_init_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    // Hash filters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,

    // Network filters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    // Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentihash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuzzyfsiohash: Option<String>,

    // Classification filters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_groups: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_techniques: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict_groups: Option<String>,

    // Misc
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_task_state: Option<MainTaskSimplifiedState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_dates_algo: Option<String>,
}

impl ReportSearchQuery {
    /// Serialize to a list of `(&str, String)` tuples for `reqwest` `.query()`.
    ///
    /// Uses `serde_json` to serialize individual fields to strings, then
    /// builds query parameters. Boolean fields are serialized as "true"/"false".
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let value = serde_json::to_value(self).unwrap_or_default();
        let mut params = Vec::new();
        if let serde_json::Value::Object(map) = value {
            for (key, val) in map {
                let s = match val {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };
                params.push((key, s));
            }
        }
        params
    }
}

/// Query parameters for `GET /api/reports` (public listing).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PublicReportsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<PageSize>,
}

impl PublicReportsQuery {
    /// Serialize to query parameter tuples.
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(p) = self.page {
            params.push(("page".to_string(), p.to_string()));
        }
        if let Some(ps) = self.page_size {
            params.push(("page_size".to_string(), ps.as_i64().to_string()));
        }
        params
    }
}

/// Query parameters for `GET /api/scan/{flow_id}/report`.
/// Supports optional `filter`, `sorting`, and `other` array query params.
#[derive(Debug, Clone, Default)]
pub struct ScanReportQuery {
    pub filter: Option<Vec<String>>,
    pub sorting: Option<Vec<String>>,
    pub other: Option<Vec<String>>,
}

impl ScanReportQuery {
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(ref values) = self.filter {
            for v in values {
                params.push(("filter".to_string(), v.clone()));
            }
        }
        if let Some(ref values) = self.sorting {
            for v in values {
                params.push(("sorting".to_string(), v.clone()));
            }
        }
        if let Some(ref values) = self.other {
            for v in values {
                params.push(("other".to_string(), v.clone()));
            }
        }
        params
    }
}

/// Query parameters for `GET /api/reports/{report_id}/{file_hash}`.
/// Same filter/sorting/other as scan-reports.
#[derive(Debug, Clone, Default)]
pub struct ReportQuery {
    pub filter: Option<Vec<String>>,
    pub sorting: Option<Vec<String>>,
    pub other: Option<Vec<String>>,
}

impl ReportQuery {
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(ref values) = self.filter {
            for v in values {
                params.push(("filter".to_string(), v.clone()));
            }
        }
        if let Some(ref values) = self.sorting {
            for v in values {
                params.push(("sorting".to_string(), v.clone()));
            }
        }
        if let Some(ref values) = self.other {
            for v in values {
                params.push(("other".to_string(), v.clone()));
            }
        }
        params
    }
}

// ---------------------------------------------------------------------------
// Stage 3: Threat Intel & Similarity query models
// ---------------------------------------------------------------------------

/// Query parameters for `GET /api/threatintel/get-similars`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetSimilarReportsQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_report_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuzzyfsiohash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentihash: Option<String>,
    /// Age limit in days (-1 = no limit, default).
    #[serde(default = "default_similar_days")]
    pub days: i64,
}

fn default_similar_days() -> i64 {
    -1
}

impl Default for GetSimilarReportsQuery {
    fn default() -> Self {
        Self {
            exclude_report_ids: None,
            imphash: None,
            ssdeep: None,
            fuzzyfsiohash: None,
            authentihash: None,
            days: -1,
        }
    }
}

impl GetSimilarReportsQuery {
    /// Serialize to query parameter tuples using repeated keys for arrays.
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(ref ids) = self.exclude_report_ids {
            for id in ids {
                params.push(("exclude_report_ids".to_string(), id.clone()));
            }
        }
        if let Some(ref v) = self.imphash {
            params.push(("imphash".to_string(), v.clone()));
        }
        if let Some(ref v) = self.ssdeep {
            params.push(("ssdeep".to_string(), v.clone()));
        }
        if let Some(ref v) = self.fuzzyfsiohash {
            params.push(("fuzzyfsiohash".to_string(), v.clone()));
        }
        if let Some(ref v) = self.authentihash {
            params.push(("authentihash".to_string(), v.clone()));
        }
        params.push(("days".to_string(), self.days.to_string()));
        params
    }
}

/// Query parameters for `GET /api/similarity-search/similarity` (deprecated endpoint).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SimilaritySearchQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_similarity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<ReportVerdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

impl SimilaritySearchQuery {
    /// Serialize to query parameter tuples using repeated keys for `tags`.
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(ref v) = self.hash {
            params.push(("hash".to_string(), v.clone()));
        }
        if let Some(v) = self.min_similarity {
            params.push(("min_similarity".to_string(), v.to_string()));
        }
        if let Some(ref v) = self.verdict {
            let verdict_str = serde_json::to_string(v).unwrap_or_default();
            // serde_json wraps enums in quotes; strip them
            let verdict_str = verdict_str.trim_matches('"');
            params.push(("verdict".to_string(), verdict_str.to_string()));
        }
        if let Some(ref tags) = self.tags {
            for tag in tags {
                params.push(("tags".to_string(), tag.clone()));
            }
        }
        params
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_search_query_empty_serializes_no_params() {
        let q = ReportSearchQuery::default();
        assert!(q.to_query_params().is_empty());
    }

    #[test]
    fn report_search_query_with_page() {
        let q = ReportSearchQuery {
            page: Some(2),
            page_size: Some(PageSize::SIZE_20),
            ..Default::default()
        };
        let params = q.to_query_params();
        assert!(params.contains(&("page".into(), "2".into())));
        assert!(params.contains(&("page_size".into(), "20".into())));
    }

    #[test]
    fn report_search_query_with_verdict() {
        let q = ReportSearchQuery {
            verdict: Some("malicious".into()),
            ..Default::default()
        };
        let params = q.to_query_params();
        assert!(params.contains(&("verdict".into(), "malicious".into())));
    }

    #[test]
    fn public_reports_query() {
        let q = PublicReportsQuery {
            page: Some(1),
            page_size: Some(PageSize::SIZE_5),
        };
        let params = q.to_query_params();
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn scan_report_query_multiple_filter() {
        let q = ScanReportQuery {
            filter: Some(vec!["general".into(), "finalVerdict".into()]),
            ..Default::default()
        };
        let params = q.to_query_params();
        assert_eq!(params.len(), 2);
        // Both entries use key "filter"
        let filter_count = params.iter().filter(|(k, _)| k == "filter").count();
        assert_eq!(filter_count, 2);
    }

    // -----------------------------------------------------------------------
    // Stage 3 query tests
    // -----------------------------------------------------------------------

    #[test]
    fn get_similar_reports_query_empty() {
        let q = GetSimilarReportsQuery::default();
        let params = q.to_query_params();
        // Only days appears when everything else is None
        assert_eq!(params.len(), 1);
        assert!(params.contains(&("days".into(), "-1".into())));
    }

    #[test]
    fn get_similar_reports_query_with_hash_selectors() {
        let q = GetSimilarReportsQuery {
            imphash: Some("abc123".into()),
            ssdeep: Some("48:xyz".into()),
            days: 7,
            ..Default::default()
        };
        let params = q.to_query_params();
        assert!(params.contains(&("imphash".into(), "abc123".into())));
        assert!(params.contains(&("ssdeep".into(), "48:xyz".into())));
        assert!(params.contains(&("days".into(), "7".into())));
    }

    #[test]
    fn get_similar_reports_query_repeated_exclude_ids() {
        let q = GetSimilarReportsQuery {
            exclude_report_ids: Some(vec!["id1".into(), "id2".into()]),
            imphash: Some("abc".into()),
            ..Default::default()
        };
        let params = q.to_query_params();
        let exclude_count = params
            .iter()
            .filter(|(k, _)| k == "exclude_report_ids")
            .count();
        assert_eq!(exclude_count, 2);
        assert!(params.contains(&("exclude_report_ids".into(), "id1".into())));
        assert!(params.contains(&("exclude_report_ids".into(), "id2".into())));
    }

    #[test]
    fn similarity_search_query_empty() {
        let q = SimilaritySearchQuery::default();
        let params = q.to_query_params();
        assert!(params.is_empty());
    }

    #[test]
    fn similarity_search_query_with_hash() {
        let q = SimilaritySearchQuery {
            hash: Some("abc123".into()),
            ..Default::default()
        };
        let params = q.to_query_params();
        assert_eq!(params.len(), 1);
        assert!(params.contains(&("hash".into(), "abc123".into())));
    }

    #[test]
    fn similarity_search_query_with_verdict() {
        let q = SimilaritySearchQuery {
            verdict: Some(ReportVerdict::Malicious),
            ..Default::default()
        };
        let params = q.to_query_params();
        assert!(params.contains(&("verdict".into(), "malicious".into())));
    }

    #[test]
    fn similarity_search_query_with_repeated_tags() {
        let q = SimilaritySearchQuery {
            tags: Some(vec!["peexe".into(), "evasive".into()]),
            ..Default::default()
        };
        let params = q.to_query_params();
        let tag_count = params.iter().filter(|(k, _)| k == "tags").count();
        assert_eq!(tag_count, 2);
        assert!(params.contains(&("tags".into(), "peexe".into())));
        assert!(params.contains(&("tags".into(), "evasive".into())));
    }

    #[test]
    fn similarity_search_query_full() {
        let q = SimilaritySearchQuery {
            hash: Some("abc123".into()),
            min_similarity: Some(50),
            verdict: Some(ReportVerdict::Suspicious),
            tags: Some(vec!["peexe".into()]),
        };
        let params = q.to_query_params();
        assert!(params.contains(&("hash".into(), "abc123".into())));
        assert!(params.contains(&("min_similarity".into(), "50".into())));
        assert!(params.contains(&("verdict".into(), "suspicious".into())));
        assert!(params.contains(&("tags".into(), "peexe".into())));
        // min_similarity with 0 default would be absent unless explicitly set
    }
}
