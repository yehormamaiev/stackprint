//! # stackprint — passive web technology fingerprinting
//!
//! Give it one HTTP response, get back what the site is built with: web server, backend framework,
//! JS frontend, CMS, WAF, CDN, database, auth scheme, and protocol features (GraphQL, gRPC,
//! WebSocket, OpenAPI, HTTP/3). **Passive and network-free** — you bring the response (from any HTTP
//! client), stackprint just reads headers and body and matches signatures. No requests are made,
//! nothing is probed, nothing is attacked.
//!
//! ```
//! use stackprint::{analyze_response, HttpResponse, WebServer};
//!
//! let resp = HttpResponse::new(
//!     200,
//!     vec![
//!         ("Server".into(), "nginx/1.25.3".into()),
//!         ("X-Powered-By".into(), "Express".into()),
//!         ("cf-ray".into(), "abc123".into()),
//!     ],
//!     Some("<html><div data-reactroot=\"\"></div></html>".into()),
//! );
//!
//! let fp = analyze_response(&resp);
//! assert!(matches!(fp.server, Some(WebServer::Nginx)));
//! assert!(fp.cdn.is_some());       // Cloudflare via cf-ray
//! assert!(fp.frontend.is_some());  // React via data-reactroot
//! ```
//!
//! Detection is best-effort heuristic matching (server headers, `X-Powered-By`, cookies, `Set-Cookie`
//! names, HTML markers, meta tags, `Alt-Svc`, …). Common stacks are caught with high confidence;
//! exotic or deliberately-hidden setups may be missed. Every hit carries a confidence score in
//! [`Fingerprint::detected_technologies`].

pub mod api;
pub mod auth;
pub mod backend;
pub mod cdn;
pub mod cms;
pub mod database;
pub mod detector;
pub mod frontend;
pub mod http;
pub mod server;
pub mod technology;
pub mod util;
pub mod version;
pub mod waf;

pub use detector::{analyze_response, merge};
pub use http::{HttpResponse, HttpVersion};
pub use technology::{
    AuthType, Backend, Cdn, Cms, Database, DetectedTechnology, Fingerprint, Frontend, TechCategory,
    Waf, WebServer,
};
