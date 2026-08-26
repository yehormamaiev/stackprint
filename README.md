# stackprint

[![CI](https://github.com/yehormamaiev/stackprint/actions/workflows/ci.yml/badge.svg)](https://github.com/yehormamaiev/stackprint/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Passive web technology fingerprinting in Rust.** Give it one HTTP response — get back what the
site is built with: web server, backend framework, JS frontend, CMS, WAF, CDN, database, auth
scheme, and protocol features (GraphQL, gRPC, WebSocket, OpenAPI, HTTP/3).

`stackprint` is **passive and network-free**. It never makes a request, probes a path, or touches the
target — you fetch the response with any HTTP client you like, and stackprint just reads the headers
and body and matches signatures. Safe to run anywhere, on anything you already have.

```rust
use stackprint::{analyze_response, HttpResponse, WebServer};

let resp = HttpResponse::new(
    200,
    vec![
        ("Server".into(),       "nginx/1.25.3".into()),
        ("X-Powered-By".into(), "Express".into()),
        ("cf-ray".into(),       "7d2f...".into()),
    ],
    Some(r#"<html><div data-reactroot=""></div></html>"#.into()),
);

let fp = analyze_response(&resp);
assert!(matches!(fp.server, Some(WebServer::Nginx)));
assert!(fp.cdn.is_some());       // Cloudflare, via cf-ray
assert!(fp.frontend.is_some());  // React, via data-reactroot
assert!(fp.backend.is_some());   // Express, via X-Powered-By
```

## What it detects

| Category | Examples |
|---|---|
| **Web server** | nginx, Apache, IIS, LiteSpeed, Caddy, Envoy, Traefik |
| **Backend** | Django, Flask, FastAPI, Rails, Spring, Laravel, Express, Next.js, ASP.NET, Gin, Phoenix |
| **Frontend** | React, Angular, Vue, Svelte, Ember, jQuery |
| **CMS** | WordPress, Drupal, Joomla, Ghost, Magento, Shopify, Strapi |
| **WAF** | Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri, F5, Fortinet |
| **CDN** | Cloudflare, Fastly, Akamai, CloudFront, Azure, KeyCDN, StackPath |
| **Database** | MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis (via leak markers) |
| **Auth** | Session, JWT, OAuth, SAML, Basic, API key, Bearer, mTLS · plus MFA hints |
| **Protocol** | GraphQL, gRPC, WebSocket, OpenAPI spec, HTTP/3 support |

Every hit carries a **confidence score** in `Fingerprint::detected_technologies`. When two responses
describe the same target (e.g. a redirect chain), `merge()` combines their fingerprints.

## Run it against a real site

```console
$ cargo run --example fingerprint_url -- https://www.rust-lang.org
server:   Nginx
cdn:      Fastly
frontend: (none)
http:     Http2
```

The example uses [`ureq`] to fetch; the library itself pulls in nothing but `serde` and `strum`.

## How it works (and its limits)

Detection is **best-effort heuristic matching** — the same idea as Wappalyzer, done from Rust with
hand-written signatures (no third-party dataset): `Server` / `X-Powered-By` / `Via` headers, cookie
and `Set-Cookie` names, HTML markers and meta-generator tags, `Alt-Svc`, error-page fingerprints, and
so on. Common stacks are caught with high confidence. Deliberately-hidden or exotic setups may be
missed or mislabeled — treat the output as strong hints, not proof.

Because it's passive, it can't confirm things that only a live probe would reveal (a hidden
`/wp-login.php`, a GraphQL endpoint that isn't advertised). That's by design: no traffic to the
target, no surprises.

## Install

```toml
[dependencies]
stackprint = { git = "https://github.com/yehormamaiev/stackprint" }
```

Once it's published to crates.io: `stackprint = "0.1"`.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.

[`ureq`]: https://crates.io/crates/ureq
