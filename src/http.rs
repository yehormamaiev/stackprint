//! Minimal HTTP response type fed to the analyzer — **bring your own HTTP client**.
//!
//! `stackprint` does not fetch anything itself: you make the request with whatever client you like
//! (`reqwest`, `ureq`, `hyper`, a raw socket…), drop the pieces into [`HttpResponse`], and pass it to
//! [`crate::analyze_response`]. That keeps the library dependency-light and network-free.

use serde::{Deserialize, Serialize};

/// One HTTP response: everything the analyzer looks at (status, headers, body, protocol version).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code (e.g. `200`).
    pub status: u16,
    /// Response headers as `(name, value)` pairs. Names are matched case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Response body, if you captured it. Many signatures work from headers alone.
    pub body: Option<String>,
    /// Negotiated HTTP version (reported back on the fingerprint).
    pub http_version: HttpVersion,
}

impl HttpResponse {
    /// Build a response from status, headers and an optional body (HTTP/1.1 assumed).
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Option<String>) -> Self {
        Self { status, headers, body, http_version: HttpVersion::Http11 }
    }

    /// Set the HTTP version (builder style).
    #[must_use]
    pub fn with_http_version(mut self, version: HttpVersion) -> Self {
        self.http_version = version;
        self
    }
}

/// Negotiated HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1 (default).
    #[default]
    Http11,
    /// HTTP/2
    Http2,
    /// HTTP/3 (QUIC).
    Http3,
}
