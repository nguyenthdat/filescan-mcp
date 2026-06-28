use std::path::Path;

use reqwest::{multipart, Method};

use crate::config::FilescanConfig;
use crate::error::FilescanError;
use crate::models::*;
use crate::query::*;

/// Facade over `reqwest::Client` that knows all Filescan HTTP details.
pub struct FilescanClient {
    http: reqwest::Client,
    base_url: String, // pre-built string form (without trailing slash)
}

impl FilescanClient {
    /// Create a new client from configuration.
    pub fn new(config: &FilescanConfig) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut api_key_header = reqwest::header::HeaderValue::from_str(&config.api_key)
            .expect("API key should be valid header value");
        api_key_header.set_sensitive(true);
        headers.insert("X-Api-Key", api_key_header);

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(config.timeout)
            .build()
            .expect("reqwest client should build");

        let base_url = config.base_url.as_str().trim_end_matches('/').to_string();

        Self { http, base_url }
    }

    /// Build an absolute URL for the given path.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    // -------------------------------------------------------------------
    // POST /api/scan/file
    // -------------------------------------------------------------------
    pub async fn scan_file(
        &self,
        file_path: &str,
        options: Option<&ScanOptions>,
    ) -> Result<ScanResponse, FilescanError> {
        let path = Path::new(file_path);

        if !path.exists() {
            return Err(FilescanError::FileNotFound {
                path: file_path.to_string(),
            });
        }
        if !path.is_file() {
            return Err(FilescanError::NotAFile {
                path: file_path.to_string(),
            });
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        let file_bytes = tokio::fs::read(path)
            .await
            .map_err(|e| FilescanError::Validation {
                message: format!("Failed to read file {file_path}: {e}"),
            })?;

        let part = multipart::Part::bytes(file_bytes)
            .file_name(file_name)
            .mime_str("application/octet-stream")
            .unwrap_or_else(|_| multipart::Part::bytes(vec![]).file_name("file"));

        let mut form = multipart::Form::new().part("file", part);

        if let Some(opts) = options {
            if let Some(ref desc) = opts.description {
                form = form.text("description", desc.clone());
            }
            if let Some(ref tags) = opts.tags {
                form = form.text("tags", tags.clone());
            }
            if let Some(ref pw) = opts.password {
                form = form.text("password", pw.clone());
            }
            if let Some(is_private) = opts.is_private {
                form = form.text("is_private", is_private.to_string());
            }
            if let Some(is_private_report) = opts.is_private_report {
                form = form.text("is_private_report", is_private_report.to_string());
            }
            if let Some(skip) = opts.skip_whitelisted {
                form = form.text("skip_whitelisted", skip.to_string());
            }
            if let Some(ref profile) = opts.scan_profile {
                form = form.text("scan_profile", profile.clone());
            }
            if let Some(ref engine) = opts.scan_engine {
                let engine_str = match engine {
                    ScanEngine::Internal => "internal",
                    ScanEngine::Mdcloud => "mdcloud",
                };
                form = form.text("scan_engine", engine_str);
            }
            if let Some(propagate_tags) = opts.propagate_tags {
                form = form.text("propagate_tags", propagate_tags.to_string());
            }
        }

        let path = "/api/scan/file";
        let url = self.url(path);
        let resp = self.http.post(&url).multipart(form).send().await?;

        self.parse_response(Method::POST, path, resp).await
    }

    // -------------------------------------------------------------------
    // POST /api/scan/url
    // -------------------------------------------------------------------
    pub async fn scan_url(
        &self,
        url_to_scan: &str,
        options: Option<&ScanOptions>,
    ) -> Result<ScanResponse, FilescanError> {
        let mut params: Vec<(String, String)> = Vec::new();
        params.push(("url".to_string(), url_to_scan.to_string()));

        if let Some(opts) = options {
            if let Some(ref desc) = opts.description {
                params.push(("description".to_string(), desc.clone()));
            }
            if let Some(ref tags) = opts.tags {
                params.push(("tags".to_string(), tags.clone()));
            }
            if let Some(ref pw) = opts.password {
                params.push(("password".to_string(), pw.clone()));
            }
            if let Some(is_private) = opts.is_private {
                params.push(("is_private".to_string(), is_private.to_string()));
            }
            if let Some(is_private_report) = opts.is_private_report {
                params.push((
                    "is_private_report".to_string(),
                    is_private_report.to_string(),
                ));
            }
            if let Some(skip) = opts.skip_whitelisted {
                params.push(("skip_whitelisted".to_string(), skip.to_string()));
            }
            if let Some(ref profile) = opts.scan_profile {
                params.push(("scan_profile".to_string(), profile.clone()));
            }
            if let Some(ref engine) = opts.scan_engine {
                let engine_str = match engine {
                    ScanEngine::Internal => "internal",
                    ScanEngine::Mdcloud => "mdcloud",
                };
                params.push(("scan_engine".to_string(), engine_str.to_string()));
            }
            if let Some(propagate_tags) = opts.propagate_tags {
                params.push(("propagate_tags".to_string(), propagate_tags.to_string()));
            }
        }

        let path = "/api/scan/url";
        let url = self.url(path);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        self.parse_response(Method::POST, path, resp).await
    }

    // -------------------------------------------------------------------
    // GET /api/scan/{flow_id}/report
    // -------------------------------------------------------------------
    pub async fn scan_reports(
        &self,
        flow_id: &str,
        query: &ScanReportQuery,
    ) -> Result<AllUploadRelatedReportsResponse, FilescanError> {
        let path = format!("/api/scan/{flow_id}/report");
        let url = self.url(&path);
        let resp = self
            .http
            .get(&url)
            .query(&query.to_query_params())
            .send()
            .await?;

        self.parse_response(Method::GET, &path, resp).await
    }

    // -------------------------------------------------------------------
    // GET /api/reports/{report_id}/{file_hash}
    // -------------------------------------------------------------------
    pub async fn report(
        &self,
        report_id: &str,
        file_hash: &str,
        query: &ReportQuery,
    ) -> Result<AllUploadRelatedReportsResponse, FilescanError> {
        let path = format!("/api/reports/{report_id}/{file_hash}");
        let url = self.url(&path);
        let resp = self
            .http
            .get(&url)
            .query(&query.to_query_params())
            .send()
            .await?;

        self.parse_response(Method::GET, &path, resp).await
    }

    // -------------------------------------------------------------------
    // GET /api/reports/search
    // -------------------------------------------------------------------
    pub async fn search_reports(
        &self,
        query: &ReportSearchQuery,
    ) -> Result<ReportSearchResponse, FilescanError> {
        let path = "/api/reports/search";
        let url = self.url(path);

        // reqwest serializes Vec<(String,String)> via .query() correctly
        let resp = self
            .http
            .get(&url)
            .query(&query.to_query_params())
            .send()
            .await?;

        self.parse_response(Method::GET, path, resp).await
    }

    // -------------------------------------------------------------------
    // POST /api/reports/search/matches
    // -------------------------------------------------------------------
    pub async fn search_matches(
        &self,
        report_ids: Vec<String>,
        query: &ReportSearchQuery,
        unique_files: Option<bool>,
    ) -> Result<Vec<MatchesResponseItem>, FilescanError> {
        let path = "/api/reports/search/matches";
        let url = self.url(path);
        let body = MatchesPayload { report_ids };

        let mut req = self
            .http
            .post(&url)
            .query(&query.to_query_params())
            .json(&body);

        if let Some(uf) = unique_files {
            req = req.query(&[("unique_files", uf.to_string())]);
        }

        let resp = req.send().await?;

        self.parse_response(Method::POST, path, resp).await
    }

    // -------------------------------------------------------------------
    // GET /api/reports (public listing)
    // -------------------------------------------------------------------
    pub async fn public_reports(
        &self,
        query: &PublicReportsQuery,
    ) -> Result<ReportSearchResponse, FilescanError> {
        let path = "/api/reports";
        let url = self.url(path);

        let resp = self
            .http
            .get(&url)
            .query(&query.to_query_params())
            .send()
            .await?;

        self.parse_response(Method::GET, path, resp).await
    }

    // -------------------------------------------------------------------
    // POST /api/files/availability
    // -------------------------------------------------------------------
    pub async fn check_file_availability(
        &self,
        hashes: &[String],
    ) -> Result<FileAvailabilityResponse, FilescanError> {
        let path = "/api/files/availability";
        let url = self.url(path);
        let resp = self.http.post(&url).json(hashes).send().await?;
        self.parse_response(Method::POST, path, resp).await
    }

    // -------------------------------------------------------------------
    // GET /api/reputation/hash (single)
    // -------------------------------------------------------------------
    pub async fn hash_reputation_single(
        &self,
        sha256: &str,
    ) -> Result<ReputationResultHash, FilescanError> {
        let path = "/api/reputation/hash";
        let url = self.url(path);
        let resp = self
            .http
            .get(&url)
            .query(&[("sha256", sha256)])
            .send()
            .await?;
        self.parse_response(Method::GET, path, resp).await
    }

    // -------------------------------------------------------------------
    // POST /api/reputation/hash (bulk)
    // -------------------------------------------------------------------
    pub async fn hash_reputation_bulk(
        &self,
        hashes: &[String],
    ) -> Result<Vec<ReputationResultHash>, FilescanError> {
        let path = "/api/reputation/hash";
        let url = self.url(path);
        let resp = self.http.post(&url).json(hashes).send().await?;
        self.parse_response(Method::POST, path, resp).await
    }

    // -------------------------------------------------------------------
    // GET /api/reputation/{ioc_type} (single)
    // -------------------------------------------------------------------
    pub async fn ioc_reputation_single(
        &self,
        ioc_type: &str,
        ioc_value: &str,
    ) -> Result<ReputationResultIoc, FilescanError> {
        let path = format!("/api/reputation/{ioc_type}");
        let url = self.url(&path);
        let resp = self
            .http
            .get(&url)
            .query(&[("ioc_value", ioc_value)])
            .send()
            .await?;
        self.parse_response(Method::GET, &path, resp).await
    }

    // -------------------------------------------------------------------
    // POST /api/reputation/{ioc_type} (bulk)
    // -------------------------------------------------------------------
    pub async fn ioc_reputation_bulk(
        &self,
        ioc_type: &str,
        values: &[String],
    ) -> Result<Vec<ReputationResultIoc>, FilescanError> {
        let path = format!("/api/reputation/{ioc_type}");
        let url = self.url(&path);
        let resp = self.http.post(&url).json(values).send().await?;
        self.parse_response(Method::POST, &path, resp).await
    }

    // -------------------------------------------------------------------
    // Response mapping
    // -------------------------------------------------------------------

    /// Parse a response body into `T` or map HTTP errors to `FilescanError`.
    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        resp: reqwest::Response,
    ) -> Result<T, FilescanError> {
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.bytes().await?;

        if status.is_success() {
            serde_json::from_slice::<T>(&body).map_err(|e| FilescanError::Decode {
                method: method.to_string(),
                path: path.to_string(),
                status: status.as_u16(),
                source: e,
            })
        } else {
            Err(FilescanError::from_api_response(
                method.as_str(),
                path,
                status.as_u16(),
                retry_after,
                &body,
            ))
        }
    }
}
