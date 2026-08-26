//! Fetch a URL and print its detected technology stack.
//!
//! ```console
//! cargo run --example fingerprint_url -- https://www.rust-lang.org
//! ```
//!
//! `stackprint` itself makes no requests — this example uses `ureq` to fetch, then hands the
//! response to the (network-free) analyzer.

use stackprint::{analyze_response, HttpResponse};

fn main() {
    let url = match std::env::args().nth(1) {
        Some(u) => u,
        None => {
            eprintln!("usage: cargo run --example fingerprint_url -- <url>");
            std::process::exit(1);
        }
    };

    // fetch (analyze error responses too — they're often the most revealing)
    let resp = match ureq::get(&url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => {
            eprintln!("request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers_names()
        .into_iter()
        .filter_map(|name| resp.header(&name).map(|v| (name.clone(), v.to_string())))
        .collect();
    let body = resp.into_string().ok();

    let fp = analyze_response(&HttpResponse::new(status, headers, body));

    row("server", &fp.server);
    row("backend", &fp.backend);
    row("frontend", &fp.frontend);
    row("cms", &fp.cms);
    row("waf", &fp.waf);
    row("cdn", &fp.cdn);
    row("database", &fp.database);
    row("auth", &fp.auth_type);
    println!("{:<10}{:?}", "http:", fp.http_version);

    let flags = [
        ("GraphQL", fp.has_graphql),
        ("gRPC", fp.has_grpc),
        ("WebSocket", fp.has_websocket),
        ("OpenAPI", fp.has_openapi_spec),
        ("HTTP/3", fp.supports_h3),
        ("MFA", fp.has_mfa),
    ];
    let present: Vec<&str> = flags.iter().filter(|(_, v)| *v).map(|(n, _)| *n).collect();
    if !present.is_empty() {
        println!("{:<10}{}", "features:", present.join(", "));
    }

    if !fp.detected_technologies.is_empty() {
        println!("\ndetected:");
        for t in &fp.detected_technologies {
            let ver = t.version.as_deref().map(|v| format!(" v{v}")).unwrap_or_default();
            println!("  {:<16} {:>3.0}%{ver}", t.name, t.confidence * 100.0);
        }
    }
}

/// Печать строки `label: value` (или `(none)`), где `value` — Display-тип под `Option`.
fn row<T: std::fmt::Display>(label: &str, value: &Option<T>) {
    let text = value.as_ref().map_or_else(|| "(none)".to_string(), ToString::to_string);
    println!("{:<10}{text}", format!("{label}:"));
}
