use std::fmt;
use std::time::Duration;

use url::Url;

use crate::error::FilescanError;

/// Configuration for the Filescan MCP server.
///
/// `FILESCAN_API_KEY` is **required** at startup.
/// `FILESCAN_BASE_URL` defaults to `https://www.filescan.io`.
pub struct FilescanConfig {
    pub(crate) base_url: Url,
    pub(crate) api_key: String,
    pub(crate) timeout: Duration,
}

impl FilescanConfig {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns `Config` error if `FILESCAN_API_KEY` is missing/empty or
    /// `FILESCAN_BASE_URL` is not a valid URL.
    pub fn from_env() -> Result<Self, FilescanError> {
        let api_key = std::env::var("FILESCAN_API_KEY").map_err(|_| FilescanError::Config {
            message: "FILESCAN_API_KEY environment variable is required".into(),
        })?;

        if api_key.trim().is_empty() {
            return Err(FilescanError::Config {
                message: "FILESCAN_API_KEY must not be empty".into(),
            });
        }

        let base_url_str = std::env::var("FILESCAN_BASE_URL")
            .unwrap_or_else(|_| "https://www.filescan.io".to_string());

        let base_url = Url::parse(&base_url_str).map_err(|e| FilescanError::Config {
            message: format!("Invalid FILESCAN_BASE_URL: {e}"),
        })?;

        let timeout = Duration::from_secs(
            std::env::var("FILESCAN_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        );

        Ok(Self {
            base_url,
            api_key,
            timeout,
        })
    }

    /// Return a reference to the base URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Create a builder for programmatic use (testing).
    pub fn builder() -> FilescanConfigBuilder {
        FilescanConfigBuilder::default()
    }
}

/// Suppress API key in debug/log output.
impl fmt::Debug for FilescanConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilescanConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[redacted]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Default)]
pub struct FilescanConfigBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    timeout: Option<Duration>,
}

impl FilescanConfigBuilder {
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    pub fn build(self) -> Result<FilescanConfig, FilescanError> {
        let api_key = self.api_key.ok_or_else(|| FilescanError::Config {
            message: "api_key is required".into(),
        })?;

        if api_key.trim().is_empty() {
            return Err(FilescanError::Config {
                message: "api_key must not be empty".into(),
            });
        }

        let base_url = Url::parse(
            &self
                .base_url
                .unwrap_or_else(|| "https://www.filescan.io".to_string()),
        )
        .map_err(|e| FilescanError::Config {
            message: format!("Invalid base_url: {e}"),
        })?;

        Ok(FilescanConfig {
            base_url,
            api_key,
            timeout: self.timeout.unwrap_or(Duration::from_secs(60)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_missing_api_key_fails() {
        let err = FilescanConfig::builder().build().unwrap_err();
        assert!(matches!(err, FilescanError::Config { .. }));
    }

    #[test]
    fn builder_empty_api_key_fails() {
        let err = FilescanConfig::builder().api_key("").build().unwrap_err();
        assert!(matches!(err, FilescanError::Config { .. }));
    }

    #[test]
    fn builder_invalid_base_url_fails() {
        let err = FilescanConfig::builder()
            .api_key("test-key")
            .base_url("not-a-url")
            .build()
            .unwrap_err();
        assert!(matches!(err, FilescanError::Config { .. }));
    }

    #[test]
    fn builder_valid_minimal_succeeds() {
        let c = FilescanConfig::builder()
            .api_key("test-key")
            .build()
            .unwrap();
        assert_eq!(c.base_url.as_str(), "https://www.filescan.io/");
        assert_eq!(c.timeout, Duration::from_secs(60));
    }

    #[test]
    fn debug_redacts_api_key() {
        let c = FilescanConfig::builder()
            .api_key("secret-123")
            .build()
            .unwrap();
        let debug = format!("{c:?}");
        assert!(!debug.contains("secret-123"));
        assert!(debug.contains("[redacted]"));
    }
}
