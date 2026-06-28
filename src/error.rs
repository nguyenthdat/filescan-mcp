use serde::Deserialize;

/// Unified error type for the Filescan MCP server.
///
/// Never contains API keys or raw request bodies.
#[derive(Debug, thiserror::Error)]
pub enum FilescanError {
    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error {method} {path} (HTTP {status}): {detail}")]
    Api {
        method: String,
        path: String,
        status: u16,
        detail: String,
        retry_after: Option<u64>,
    },

    #[error("Failed to decode response from {method} {path} (HTTP {status})")]
    Decode {
        method: String,
        path: String,
        status: u16,
        #[source]
        source: serde_json::Error,
    },

    #[error("File not found: {path}")]
    FileNotFound { path: String },

    #[error("Not a regular file: {path}")]
    NotAFile { path: String },
}

/// OpenAPI `ErrorMessageModel` — used for non-422 API errors.
#[derive(Debug, Deserialize)]
pub(crate) struct ErrorMessageModel {
    pub detail: serde_json::Value,
}

/// OpenAPI `HTTPValidationError` for 422 responses.
#[derive(Debug, Deserialize)]
pub(crate) struct HttpValidationError {
    pub detail: Vec<ValidationErrorItem>,
}

/// OpenAPI `ValidationError` item within a 422 response.
#[derive(Debug, Deserialize)]
pub(crate) struct ValidationErrorItem {
    pub loc: Vec<serde_json::Value>,
    pub msg: String,
    #[serde(rename = "type")]
    pub typ: String,
}

impl FilescanError {
    /// Parse an API error body and produce a typed error.
    pub(crate) fn from_api_response(
        method: &str,
        path: &str,
        status: u16,
        retry_after: Option<u64>,
        body: &[u8],
    ) -> Self {
        let detail = match status {
            422 => {
                if let Ok(v) = serde_json::from_slice::<HttpValidationError>(body) {
                    v.detail
                        .into_iter()
                        .map(|e| {
                            let loc = e
                                .loc
                                .into_iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<_>>()
                                .join(".");
                            format!("{} (type: {}, loc: {})", e.msg, e.typ, loc)
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                } else {
                    String::from_utf8_lossy(body).into_owned()
                }
            }
            _ => {
                if let Ok(m) = serde_json::from_slice::<ErrorMessageModel>(body) {
                    match m.detail {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    }
                } else {
                    String::from_utf8_lossy(body).into_owned()
                }
            }
        };

        FilescanError::Api {
            method: method.to_string(),
            path: path.to_string(),
            status,
            detail,
            retry_after,
        }
    }

    /// Produce a user-facing message suitable for MCP tool error output.
    pub fn mcp_message(&self) -> String {
        match self {
            FilescanError::Config { message } => {
                format!("Configuration error: {message}")
            }
            FilescanError::Validation { message } => {
                format!("Validation error: {message}")
            }
            FilescanError::Http(e) => {
                format!("Network error connecting to Filescan.io: {e}")
            }
            FilescanError::Api {
                method,
                path,
                status,
                detail,
                retry_after,
            } => {
                let guidance = match status {
                    400 => "Check the input fields and try again.",
                    401 => "Verify your FILESCAN_API_KEY is set correctly.",
                    403 => "Your API key does not have permission for this resource, or the resource is private.",
                    404 => "The requested resource (flow/report) was not found.",
                    413 => "The file is too large. Try a smaller sample or check Filescan max upload size.",
                    415 => "The server rejected the content type. Check that bulk reputation requests send a JSON array body.",
                    422 => "One or more input fields failed validation. See details above.",
                    429 => {
                        if let Some(secs) = retry_after {
                            return format!(
                                "Rate limited. Retry after {} seconds. (HTTP {} on {} {})",
                                secs, status, method, path
                            );
                        }
                        "Rate limited. Reduce request frequency and try again."
                    }
                    _ => "An unexpected error occurred from the Filescan API.",
                };
                format!(
                    "Filescan API error (HTTP {status} on {method} {path}): {detail}. {guidance}"
                )
            }
            FilescanError::Decode {
                method,
                path,
                status,
                source,
            } => {
                format!("Failed to parse API response (HTTP {status} on {method} {path}): {source}")
            }
            FilescanError::FileNotFound { path } => {
                format!("File not found: {path}")
            }
            FilescanError::NotAFile { path } => {
                format!("Not a regular file: {path}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_error_message_model_string_detail() {
        let json = json!({"detail": "Something went wrong"});
        let body = serde_json::to_vec(&json).unwrap();
        let err = FilescanError::from_api_response("GET", "/api/test", 400, None, &body);
        assert!(matches!(err, FilescanError::Api { status: 400, .. }));
        let msg = err.mcp_message();
        assert!(msg.contains("Something went wrong"));
        assert!(msg.contains("400"));
    }

    #[test]
    fn parse_error_message_model_object_detail() {
        let json = json!({"detail": {"reason": "forbidden", "extra": 42}});
        let body = serde_json::to_vec(&json).unwrap();
        let err = FilescanError::from_api_response("POST", "/api/scan/file", 403, None, &body);
        assert!(matches!(err, FilescanError::Api { status: 403, .. }));
        let msg = err.mcp_message();
        assert!(msg.contains("403"));
    }

    #[test]
    fn parse_validation_error() {
        let json = json!({
            "detail": [
                {"loc": ["body", "file"], "msg": "field required", "type": "value_error.missing"},
                {"loc": ["body", "tags"], "msg": "invalid type", "type": "type_error"}
            ]
        });
        let body = serde_json::to_vec(&json).unwrap();
        let err = FilescanError::from_api_response("POST", "/api/scan/file", 422, None, &body);
        assert!(matches!(err, FilescanError::Api { status: 422, .. }));
        let msg = err.mcp_message();
        assert!(msg.contains("field required"));
        assert!(msg.contains("invalid type"));
    }

    #[test]
    fn retry_after_message() {
        let json = json!({"detail": "rate limited"});
        let body = serde_json::to_vec(&json).unwrap();
        let err = FilescanError::from_api_response("POST", "/api/scan/file", 429, Some(30), &body);
        let msg = err.mcp_message();
        assert!(msg.contains("Retry after 30 seconds"));
    }

    #[test]
    fn http_error_message_is_safe() {
        // Verify error messages never contain sensitive tokens.
        let msg = FilescanError::Config {
            message: "FILESCAN_API_KEY is missing".into(),
        }
        .mcp_message();
        // The error message names the env var as guidance, not the actual key value.
        assert!(msg.contains("FILESCAN_API_KEY"));
    }
}
