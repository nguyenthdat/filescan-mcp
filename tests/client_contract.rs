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
    assert_eq!(result.priority.max_possible, 100);
}

#[tokio::test]
async fn scan_url_with_options() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/scan/url")
            .body_contains("description=test+file")
            .body_contains("tags=trojan");
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
        propagate_tags: None,
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
        )
        .await
        .unwrap();
    mock.assert();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].report_id, "id1");
    assert_eq!(result[0].matches.len(), 1);
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
