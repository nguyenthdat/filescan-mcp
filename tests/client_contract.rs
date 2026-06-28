use httpmock::prelude::*;

use filescan_mcp::client::FilescanClient;
use filescan_mcp::config::FilescanConfig;
use filescan_mcp::models::*;
use filescan_mcp::query::*;

/// Build a client pointed at a mock server.
fn mock_client(server: &MockServer) -> FilescanClient {
    let base_url = server.url("");
    let config = FilescanConfig::builder()
        .api_key("test-mock-key")
        .base_url(base_url)
        .build()
        .unwrap();
    FilescanClient::new(&config)
}

#[tokio::test]
async fn scan_url_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/scan/url")
            .header("X-Api-Key", "test-mock-key");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"flow_id":"flow-123","priority":{"applied":100,"max_posibble":100}}"#);
    });

    let client = mock_client(&server);
    let result = client
        .scan_url("https://example.com/malware.exe", None)
        .await
        .unwrap();
    mock.assert();

    assert_eq!(result.flow_id, "flow-123");
    assert_eq!(result.priority.max_possible, Some(100));
}

#[tokio::test]
async fn scan_url_with_options() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/scan/url")
            .body_contains("description=test+file")
            .body_contains("tags=trojan")
            .body_contains("propagate_tags=true");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"flow_id":"flow-456","priority":{"applied":50,"max_posibble":100}}"#);
    });

    let client = mock_client(&server);
    let options = ScanOptions {
        description: Some("test file".into()),
        tags: Some("trojan".into()),
        password: None,
        is_private: None,
        is_private_report: None,
        skip_whitelisted: None,
        scan_profile: None,
        scan_engine: Some(ScanEngine::Internal),
        propagate_tags: Some(true),
    };
    let result = client
        .scan_url("https://example.com/malware.exe", Some(&options))
        .await
        .unwrap();
    mock.assert();
    assert_eq!(result.flow_id, "flow-456");
}

#[tokio::test]
async fn scan_url_401_error() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/api/scan/url");
        then.status(401)
            .header("content-type", "application/json")
            .body(r#"{"detail":"Not authorized"}"#);
    });

    let client = mock_client(&server);
    let err = client
        .scan_url("https://example.com/malware.exe", None)
        .await
        .unwrap_err();
    mock.assert();

    let msg = err.mcp_message();
    assert!(msg.contains("401"));
    assert!(msg.contains("FILESCAN_API_KEY"));
}

#[tokio::test]
async fn scan_url_429_with_retry_after() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/api/scan/url");
        then.status(429)
            .header("retry-after", "45")
            .header("content-type", "application/json")
            .body(r#"{"detail":"Too many requests"}"#);
    });

    let client = mock_client(&server);
    let err = client
        .scan_url("https://example.com/malware.exe", None)
        .await
        .unwrap_err();
    mock.assert();

    let msg = err.mcp_message();
    assert!(msg.contains("Retry after 45 seconds"));
}

#[tokio::test]
async fn scan_file_file_not_found() {
    let server = MockServer::start();
    let client = mock_client(&server);
    let err = client
        .scan_file("/nonexistent/path/file.exe", None)
        .await
        .unwrap_err();
    let msg = err.mcp_message();
    assert!(msg.contains("File not found"));
}

#[tokio::test]
async fn scan_file_sends_propagate_tags() {
    use std::io::Write;

    let server = MockServer::start();
    let dir = std::env::temp_dir();
    let file_path = dir.join("filescan_test_propagate.txt");
    let mut f = std::fs::File::create(&file_path).unwrap();
    f.write_all(b"hello filescan").unwrap();

    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/scan/file")
            .header("X-Api-Key", "test-mock-key")
            // Verify propagate_tags appears somewhere in the multipart body
            .body_contains("propagate_tags");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"flow_id":"flow-propagate","priority":{"applied":100}}"#);
    });

    let client = mock_client(&server);
    let options = ScanOptions {
        propagate_tags: Some(false),
        description: Some("test propagate".into()),
        ..Default::default()
    };
    let result = client
        .scan_file(file_path.to_str().unwrap(), Some(&options))
        .await
        .unwrap();
    mock.assert();
    assert_eq!(result.flow_id, "flow-propagate");
    assert_eq!(result.priority.max_possible, None);

    // Cleanup
    let _ = std::fs::remove_file(&file_path);
}

#[tokio::test]
async fn search_reports_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/reports/search")
            .query_param("verdict", "malicious")
            .query_param("page", "1");
        then.status(200).body(
            r#"{"items":[{"report_id":"r1","file_name":"bad.exe"}],"count":1,"method":"and"}"#,
        );
    });

    let client = mock_client(&server);
    let query = ReportSearchQuery {
        verdict: Some("malicious".into()),
        page: Some(1),
        ..Default::default()
    };
    let result = client.search_reports(&query).await.unwrap();
    mock.assert();

    assert_eq!(result.count, 1);
    assert_eq!(result.items.len(), 1);
}

#[tokio::test]
async fn search_matches_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/reports/search/matches")
            .json_body(serde_json::json!({"reports_ids": ["id1", "id2"]}));
        then.status(200).body(
            r#"[
                {
                    "report_id": "id1",
                    "matches": [
                        {
                            "origin": {"sha256": "abc", "relation": "same"},
                            "matches": {"count": 3}
                        }
                    ]
                }
            ]"#,
        );
    });

    let client = mock_client(&server);
    let result = client
        .search_matches(
            vec!["id1".into(), "id2".into()],
            &ReportSearchQuery::default(),
            None,
        )
        .await
        .unwrap();
    mock.assert();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].report_id, "id1");
    assert_eq!(result[0].matches.len(), 1);
}

#[tokio::test]
async fn search_matches_with_unique_files() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/reports/search/matches")
            .query_param("unique_files", "true")
            .json_body(serde_json::json!({"reports_ids": ["id1"]}));
        then.status(200)
            .body(r#"[{"report_id":"id1","matches":[]}]"#);
    });

    let client = mock_client(&server);
    let result = client
        .search_matches(
            vec!["id1".into()],
            &ReportSearchQuery::default(),
            Some(true),
        )
        .await
        .unwrap();
    mock.assert();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].report_id, "id1");
}

#[tokio::test]
async fn public_reports_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/reports")
            .query_param("page", "1")
            .query_param("page_size", "10");
        then.status(200)
            .body(r#"{"items":[{"report_id":"r1"}],"count":1,"method":"and"}"#);
    });

    let client = mock_client(&server);
    let query = PublicReportsQuery {
        page: Some(1),
        page_size: Some(PageSize::SIZE_10),
    };
    let result = client.public_reports(&query).await.unwrap();
    mock.assert();

    assert_eq!(result.count, 1);
}

#[tokio::test]
async fn get_scan_reports_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/api/scan/flow-1/report");
        then.status(200).body(
            r#"{"flowId":"flow-1","allFinished":true,"state":"finished","reports":{"r1":{"overallState":"success"}}}"#,
        );
    });

    let client = mock_client(&server);
    let query = ScanReportQuery::default();
    let result = client.scan_reports("flow-1", &query).await.unwrap();
    mock.assert();

    assert_eq!(result.flow_id.unwrap(), "flow-1");
    assert!(result.all_finished.unwrap());
}

#[tokio::test]
async fn get_report_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/api/reports/r-123/abc123");
        then.status(200)
            .body(r#"{"flowId":"flow-1","reports":{"r-123":{"overallState":"success"}}}"#);
    });

    let client = mock_client(&server);
    let query = ReportQuery::default();
    let result = client.report("r-123", "abc123", &query).await.unwrap();
    mock.assert();

    assert!(result.flow_id.is_some());
}

#[tokio::test]
async fn api_422_validation_error() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/api/scan/url");
        then.status(422).body(
            r#"{"detail":[{"loc":["body","url"],"msg":"field required","type":"value_error.missing"}]}"#,
        );
    });

    let client = mock_client(&server);
    let err = client.scan_url("", None).await.unwrap_err();
    mock.assert();

    let msg = err.mcp_message();
    assert!(msg.contains("422"));
    assert!(msg.contains("field required"));
}

#[tokio::test]
async fn api_404_not_found() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/api/scan/unknown/report");
        then.status(404).body(r#"{"detail":"Flow not found"}"#);
    });

    let client = mock_client(&server);
    let err = client
        .scan_reports("unknown", &ScanReportQuery::default())
        .await
        .unwrap_err();
    mock.assert();

    let msg = err.mcp_message();
    assert!(msg.contains("404"));
    assert!(msg.contains("not found"));
}

// ---------------------------------------------------------------------------
// Stage 2: Availability & Reputation contract tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_file_availability_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/files/availability")
            .header("X-Api-Key", "test-mock-key")
            .json_body(serde_json::json!(["abc123", "def456"]));
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"abc123":true,"def456":false}"#);
    });

    let client = mock_client(&server);
    let hashes = vec!["abc123".to_string(), "def456".to_string()];
    let result = client.check_file_availability(&hashes).await.unwrap();
    mock.assert();

    assert_eq!(result.available.len(), 2);
    assert_eq!(result.available.get("abc123"), Some(&true));
    assert_eq!(result.available.get("def456"), Some(&false));
}

#[tokio::test]
async fn check_file_availability_empty_body() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/files/availability")
            .json_body(serde_json::json!([]));
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{}"#);
    });

    let client = mock_client(&server);
    let result = client.check_file_availability(&[]).await.unwrap();
    mock.assert();
    assert!(result.available.is_empty());
}

#[tokio::test]
async fn hash_reputation_single_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/reputation/hash")
            .query_param("sha256", "abc123");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{
                    "sha256":"abc123",
                    "overall_verdict":"malicious",
                    "filescan_reports":[
                        {"verdict":"malicious","report_id":"r1"}
                    ]
                }"#,
            );
    });

    let client = mock_client(&server);
    let result = client.hash_reputation_single("abc123").await.unwrap();
    mock.assert();

    assert_eq!(result.sha256, "abc123");
    assert!(matches!(result.overall_verdict, ReportVerdict::Malicious));
    assert_eq!(result.filescan_reports.len(), 1);
    assert!(result.fuzzyhash.is_none());
    assert!(result.mdcloud.is_none());
}

#[tokio::test]
async fn hash_reputation_bulk_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/reputation/hash")
            .json_body(serde_json::json!(["abc123", "def456"]));
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"[
                    {
                        "sha256":"abc123",
                        "overall_verdict":"benign",
                        "filescan_reports":[]
                    },
                    {
                        "sha256":"def456",
                        "overall_verdict":"malicious",
                        "filescan_reports":[]
                    }
                ]"#,
            );
    });

    let client = mock_client(&server);
    let hashes = vec!["abc123".to_string(), "def456".to_string()];
    let results = client.hash_reputation_bulk(&hashes).await.unwrap();
    mock.assert();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].sha256, "abc123");
    assert!(matches!(results[0].overall_verdict, ReportVerdict::Benign));
    assert!(matches!(
        results[1].overall_verdict,
        ReportVerdict::Malicious
    ));
}

#[tokio::test]
async fn ioc_reputation_single_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/reputation/domain")
            .query_param("ioc_value", "example.com");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{
                    "ioc_type":"domain",
                    "ioc_value":"example.com",
                    "overall_verdict":"unknown",
                    "filescan_reports":[]
                }"#,
            );
    });

    let client = mock_client(&server);
    let result = client
        .ioc_reputation_single("domain", "example.com")
        .await
        .unwrap();
    mock.assert();

    assert_eq!(result.ioc_type, "domain");
    assert_eq!(result.ioc_value, "example.com");
    assert!(matches!(result.overall_verdict, ReportVerdict::Unknown));
    assert!(result.mdcloud.is_none());
}

#[tokio::test]
async fn ioc_reputation_bulk_success() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/reputation/ip")
            .json_body(serde_json::json!(["1.2.3.4", "5.6.7.8"]));
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"[
                    {
                        "ioc_type":"ip",
                        "ioc_value":"1.2.3.4",
                        "overall_verdict":"suspicious",
                        "filescan_reports":[]
                    },
                    {
                        "ioc_type":"ip",
                        "ioc_value":"5.6.7.8",
                        "overall_verdict":"unknown",
                        "filescan_reports":[]
                    }
                ]"#,
            );
    });

    let client = mock_client(&server);
    let values = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
    let results = client.ioc_reputation_bulk("ip", &values).await.unwrap();
    mock.assert();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].ioc_type, "ip");
    assert_eq!(results[1].ioc_value, "5.6.7.8");
}

#[tokio::test]
async fn ioc_reputation_url_single() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/reputation/url")
            .query_param("ioc_value", "https://example.com");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{
                    "ioc_type":"url",
                    "ioc_value":"https://example.com",
                    "overall_verdict":"malicious",
                    "mdcloud":{"scan_time":"2025-01-01T00:00:00","detected":5},
                    "filescan_reports":[
                        {"verdict":"malicious","report_id":"r2","report_date":"01/01/2025, 00:00:00"}
                    ]
                }"#,
            );
    });

    let client = mock_client(&server);
    let result = client
        .ioc_reputation_single("url", "https://example.com")
        .await
        .unwrap();
    mock.assert();

    assert_eq!(result.ioc_type, "url");
    assert!(result.mdcloud.is_some());
    assert_eq!(result.mdcloud.unwrap().detected, 5);
    assert_eq!(result.filescan_reports.len(), 1);
    assert_eq!(
        result.filescan_reports[0].report_date.as_deref(),
        Some("01/01/2025, 00:00:00")
    );
}

#[tokio::test]
async fn reputation_415_unsupported_media_type() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/reputation/hash")
            .query_param("sha256", "abc");
        then.status(415)
            .header("content-type", "application/json")
            .body(r#"{"detail":"Unsupported media type"}"#);
    });

    let client = mock_client(&server);
    let err = client.hash_reputation_single("abc").await.unwrap_err();
    mock.assert();

    let msg = err.mcp_message();
    assert!(msg.contains("415"));
    assert!(msg.contains("content type"));
}

#[tokio::test]
async fn availability_returns_422() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/api/files/availability");
        then.status(422).body(
            r#"{"detail":[{"loc":["body"],"msg":"Invalid hash format","type":"value_error"}]}"#,
        );
    });

    let client = mock_client(&server);
    let err = client
        .check_file_availability(&["bad".to_string()])
        .await
        .unwrap_err();
    mock.assert();

    let msg = err.mcp_message();
    assert!(msg.contains("422"));
    assert!(msg.contains("Invalid hash format"));
}
