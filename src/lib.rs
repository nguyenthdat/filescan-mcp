//! MCP server for Filescan.io — scan files/URLs, search reports, and query
//! threat intelligence.
//!
//! Environment variables:
//! - `FILESCAN_API_KEY` (required) — Filescan.io API key
//! - `FILESCAN_BASE_URL` (optional) — defaults to `https://www.filescan.io`

pub mod client;
pub mod config;
pub mod error;
pub mod models;
pub mod query;
pub mod tools;
