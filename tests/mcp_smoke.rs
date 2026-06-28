use filescan_mcp::config::FilescanConfig;
use filescan_mcp::models::*;
use filescan_mcp::query::*;

#[test]
fn page_size_from_i64_valid() {
    assert!(PageSize::from_i64(5).is_ok());
    assert!(PageSize::from_i64(10).is_ok());
    assert!(PageSize::from_i64(20).is_ok());
}

#[test]
fn page_size_from_i64_invalid() {
    assert!(PageSize::from_i64(0).is_err());
    assert!(PageSize::from_i64(15).is_err());
    assert!(PageSize::from_i64(100).is_err());
}

#[test]
fn page_size_deserialize_valid() {
    let ps: PageSize = serde_json::from_str("5").unwrap();
    assert_eq!(ps.as_i64(), 5);
    let ps: PageSize = serde_json::from_str("10").unwrap();
    assert_eq!(ps.as_i64(), 10);
    let ps: PageSize = serde_json::from_str("20").unwrap();
    assert_eq!(ps.as_i64(), 20);
}

#[test]
fn page_size_deserialize_invalid_rejected() {
    let err = serde_json::from_str::<PageSize>("7").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("page_size must be 5, 10, or 20"));
    assert!(msg.contains("7"));

    let err = serde_json::from_str::<PageSize>("0").unwrap_err();
    assert!(err.to_string().contains("page_size must be 5, 10, or 20"));

    let err = serde_json::from_str::<PageSize>("100").unwrap_err();
    assert!(err.to_string().contains("page_size must be 5, 10, or 20"));
}

#[test]
fn scan_priority_response_handles_typo() {
    let json = r#"{"applied": 100, "max_posibble": 200}"#;
    let p: ScanPriorityResponse = serde_json::from_str(json).unwrap();
    assert_eq!(p.max_possible, Some(200));
    assert_eq!(p.applied, 100);

    let json_alias = r#"{"applied": 50, "max_possible": 100}"#;
    let p_alias: ScanPriorityResponse = serde_json::from_str(json_alias).unwrap();
    assert_eq!(p_alias.max_possible, Some(100));

    let json2 = r#"{"applied": 50}"#;
    let p2 = serde_json::from_str::<ScanPriorityResponse>(json2).unwrap();
    assert_eq!(p2.max_possible, None);
}

#[test]
fn all_upload_reports_response_parses_full() {
    let json = r#"{
        "flowId": "f123",
        "allFinished": true,
        "allFilesDownloadFinished": false,
        "allAdditionalStepsDone": true,
        "reportsAmount": 3,
        "priority": "max",
        "pollPause": 5,
        "state": "finished",
        "scanStartedDate": "2025-01-01",
        "positionInQueue": 0,
        "queueSize": 10,
        "fileSize": 1024,
        "fileReadProgressBytes": 1024,
        "reports": {
            "r1": {"overallState": "success"}
        }
    }"#;
    let r: AllUploadRelatedReportsResponse = serde_json::from_str(json).unwrap();
    assert_eq!(r.flow_id.unwrap(), "f123");
    assert!(r.all_finished.unwrap());
    assert_eq!(r.reports_amount.unwrap(), 3);
    assert!(r.reports.is_object());
}

#[test]
fn report_search_response_parses() {
    let json = r#"{
        "items": [{"id": 1}, {"id": 2}],
        "count": 2,
        "count_search_params": 100,
        "earliest_dates_covered": true,
        "method": "and",
        "dbs_sync": true
    }"#;
    let r: ReportSearchResponse = serde_json::from_str(json).unwrap();
    assert_eq!(r.items.len(), 2);
    assert_eq!(r.count, 2);
    assert_eq!(r.count_search_params.unwrap(), 100);
    assert_eq!(r.method, "and");
    assert!(r.dbs_sync.unwrap());
}

#[test]
fn report_search_query_empty_to_params() {
    let q = ReportSearchQuery::default();
    assert!(q.to_query_params().is_empty());
}

#[test]
fn report_search_query_full_to_params() {
    let q = ReportSearchQuery {
        verdict: Some("malicious".into()),
        sha256: Some("abc123".into()),
        page: Some(1),
        page_size: Some(PageSize::SIZE_20),
        method: Some(ReportSearchMethod::And),
        derived_files: Some(true),
        no_date_limit: Some(false),
        ..Default::default()
    };
    let params = q.to_query_params();
    assert!(params.contains(&("verdict".into(), "malicious".into())));
    assert!(params.contains(&("sha256".into(), "abc123".into())));
    assert!(params.contains(&("page".into(), "1".into())));
    assert!(params.contains(&("page_size".into(), "20".into())));
    assert!(params.contains(&("method".into(), "and".into())));
}

#[test]
fn config_builder_with_custom_base_url() {
    let c = FilescanConfig::builder()
        .api_key("key1")
        .base_url("https://custom.filescan.io/api")
        .build()
        .unwrap();
    assert_eq!(c.base_url().as_str(), "https://custom.filescan.io/api");
}

#[test]
fn scan_file_input_serializes_options() {
    let input = ScanFileToolInput {
        file_path: "/tmp/test.exe".into(),
        options: Some(ScanOptions {
            description: Some("test desc".into()),
            scan_engine: Some(ScanEngine::Internal),
            ..Default::default()
        }),
    };
    let json = serde_json::to_string(&input).unwrap();
    assert!(json.contains("test desc"));
    assert!(json.contains("internal"));
}

#[test]
fn search_matches_input_serializes_unique_files() {
    // unique_files should appear at the top level of SearchMatchesInput, not
    // inside the flattened ReportSearchQuery.
    let input = filescan_mcp::tools::SearchMatchesInput {
        report_ids: vec!["r1".into()],
        unique_files: Some(true),
        query: ReportSearchQuery::default(),
    };
    let json = serde_json::to_string(&input).unwrap();
    assert!(json.contains("\"unique_files\":true"));
    assert!(json.contains("\"report_ids\":[\"r1\"]"));
}

#[test]
fn search_matches_input_without_unique_files() {
    let input = filescan_mcp::tools::SearchMatchesInput {
        report_ids: vec!["r1".into()],
        unique_files: None,
        query: ReportSearchQuery::default(),
    };
    let json = serde_json::to_string(&input).unwrap();
    assert!(!json.contains("unique_files"));
}

#[test]
fn page_size_json_schema_is_integer_type() {
    let schema = schemars::schema_for!(PageSize);
    let schema_json = serde_json::to_value(schema).unwrap();
    assert_eq!(schema_json["type"], "integer");
}
