//! Passive fingerprint analysis: derive a technology [`Fingerprint`] from one HTTP response.

use crate::http::HttpResponse;
use crate::technology::{DetectedTechnology, Fingerprint, TechCategory};
use crate::{api, auth, backend, cdn, cms, database, frontend, server, version, waf};

pub fn analyze_response(response: &HttpResponse) -> Fingerprint {
    let headers = &response.headers;
    let body = response.body.as_deref();
    let mut fp = Fingerprint::default();

    if let Some(det) = server::detect_server(headers) {
        add_tech(
            &mut fp,
            &det.server.to_string(),
            det.version,
            TechCategory::Server,
            det.confidence,
        );
        fp.server = Some(det.server);
    }

    if let Some(det) = waf::detect_waf(headers, body) {
        add_tech(
            &mut fp,
            &det.waf.to_string(),
            None,
            TechCategory::Waf,
            det.confidence,
        );
        fp.waf = Some(det.waf);
    }

    if let Some(detected_cdn) = cdn::detect_cdn(headers) {
        add_tech(
            &mut fp,
            &detected_cdn.to_string(),
            None,
            TechCategory::Cdn,
            0.9,
        );
        fp.cdn = Some(detected_cdn);
    }

    if let Some(det) = backend::detect_backend(headers, body) {
        add_tech(
            &mut fp,
            &det.backend.to_string(),
            det.version,
            TechCategory::Framework,
            det.confidence,
        );
        fp.backend = Some(det.backend);
    }

    if let Some(det) = frontend::detect_frontend(headers, body) {
        add_tech(
            &mut fp,
            &det.frontend.to_string(),
            det.version,
            TechCategory::JsFramework,
            det.confidence,
        );
        fp.frontend = Some(det.frontend);
    }

    if let Some(det) = cms::detect_cms(headers, body) {
        add_tech(
            &mut fp,
            &det.cms.to_string(),
            det.version,
            TechCategory::Cms,
            det.confidence,
        );
        fp.cms = Some(det.cms);
    }

    if let Some(detected_db) = database::detect_database(headers, body) {
        add_tech(
            &mut fp,
            &detected_db.to_string(),
            None,
            TechCategory::Database,
            0.7,
        );
        fp.database = Some(detected_db);
    }

    fp.auth_type = auth::detect_auth_type(headers, body);
    fp.has_mfa = auth::detect_mfa(headers, body);

    fp.has_graphql = api::detect_graphql_from_response(headers, body);
    fp.has_grpc = api::detect_grpc(headers);
    fp.has_websocket = api::detect_websocket_from_response(headers, body);
    fp.has_openapi_spec = api::detect_openapi_from_response(body);

    fp.http_version = Some(response.http_version);
    fp.supports_h3 = version::detect_h3_support(headers);

    fp.raw_headers.clone_from(&response.headers);

    fp
}

pub fn merge(base: &mut Fingerprint, other: &Fingerprint) {
    if base.server.is_none() {
        base.server.clone_from(&other.server);
    }
    if base.backend.is_none() {
        base.backend.clone_from(&other.backend);
    }
    if base.frontend.is_none() {
        base.frontend.clone_from(&other.frontend);
    }
    if base.cms.is_none() {
        base.cms.clone_from(&other.cms);
    }
    if base.waf.is_none() {
        base.waf.clone_from(&other.waf);
    }
    if base.database.is_none() {
        base.database.clone_from(&other.database);
    }
    if base.cdn.is_none() {
        base.cdn.clone_from(&other.cdn);
    }
    if base.auth_type.is_none() {
        base.auth_type = other.auth_type;
    }
    if base.http_version.is_none() {
        base.http_version = other.http_version;
    }

    base.has_graphql |= other.has_graphql;
    base.has_grpc |= other.has_grpc;
    base.has_websocket |= other.has_websocket;
    base.has_openapi_spec |= other.has_openapi_spec;
    base.has_mfa |= other.has_mfa;
    base.supports_h3 |= other.supports_h3;

    for tech in &other.detected_technologies {
        if !base
            .detected_technologies
            .iter()
            .any(|t| t.name == tech.name)
        {
            base.detected_technologies.push(tech.clone());
        }
    }
}

fn add_tech(
    fp: &mut Fingerprint,
    name: &str,
    version: Option<String>,
    category: TechCategory,
    confidence: f64,
) {
    fp.detected_technologies.push(DetectedTechnology {
        name: name.to_string(),
        version,
        category,
        confidence,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpVersion;
    use crate::technology::*;

    fn make_response(status: u16, headers: Vec<(&str, &str)>, body_text: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: if body_text.is_empty() {
                None
            } else {
                Some(body_text.to_string())
            },
            http_version: HttpVersion::Http11,
        }
    }

    #[test]
    fn full_passive_analysis() {
        let resp = make_response(
            200,
            vec![
                ("Server", "nginx/1.22.1"),
                ("cf-ray", "abc123"),
                ("X-Powered-By", "Express"),
                ("Alt-Svc", "h3=\":443\""),
                ("Set-Cookie", "connect.sid=abc; Path=/"),
            ],
            r#"<html><div data-reactroot="">
                <script src="/app.js"></script>
                var ws = new WebSocket("wss://example.com/ws");
            </div></html>"#,
        );

        let fp = analyze_response(&resp);

        assert!(matches!(fp.server, Some(WebServer::Nginx)));
        assert!(matches!(fp.waf, Some(Waf::Cloudflare)));
        assert!(matches!(fp.cdn, Some(Cdn::Cloudflare)));
        assert!(matches!(fp.backend, Some(Backend::Express)));
        assert!(matches!(fp.frontend, Some(Frontend::React)));
        assert_eq!(fp.http_version, Some(HttpVersion::Http11));
        assert!(fp.supports_h3);
        assert!(fp.has_websocket);
        assert!(!fp.detected_technologies.is_empty());
    }

    #[test]
    fn wordpress_detection() {
        let resp = make_response(
            200,
            vec![("Server", "Apache/2.4.52")],
            r#"<html>
                <meta name="generator" content="WordPress 6.5.2" />
                <link rel="stylesheet" href="/wp-content/themes/theme/style.css" />
            </html>"#,
        );

        let fp = analyze_response(&resp);

        assert!(matches!(fp.server, Some(WebServer::Apache)));
        assert!(matches!(fp.cms, Some(Cms::WordPress)));
    }

    #[test]
    fn django_detection() {
        let resp = make_response(
            200,
            vec![
                ("X-Django-Debug", "true"),
                ("Set-Cookie", "csrftoken=abc123; Path=/"),
            ],
            "",
        );

        let fp = analyze_response(&resp);

        assert!(matches!(fp.backend, Some(Backend::Django)));
    }

    #[test]
    fn spring_boot_error_page() {
        let resp = make_response(
            500,
            vec![],
            "Whitelabel Error Page - This application has no explicit mapping",
        );

        let fp = analyze_response(&resp);

        assert!(matches!(fp.backend, Some(Backend::SpringBoot)));
    }

    #[test]
    fn spring_from_jsessionid() {
        let resp = make_response(200, vec![("Set-Cookie", "JSESSIONID=abc; Path=/")], "");

        let fp = analyze_response(&resp);

        assert!(matches!(fp.backend, Some(Backend::Spring)));
    }

    #[test]
    fn database_error_detection() {
        let resp = make_response(
            500,
            vec![],
            "ERROR: relation \"users\" does not exist\nPostgreSQL error",
        );

        let fp = analyze_response(&resp);

        assert!(matches!(fp.database, Some(Database::PostgreSQL)));
    }

    #[test]
    fn auth_detection() {
        let resp = make_response(401, vec![("WWW-Authenticate", "Bearer realm=\"api\"")], "");

        let fp = analyze_response(&resp);

        assert_eq!(fp.auth_type, Some(AuthType::BearerToken));
    }

    #[test]
    fn mfa_detection() {
        let resp = make_response(
            200,
            vec![],
            "Please enter your two-factor authentication code",
        );

        let fp = analyze_response(&resp);

        assert!(fp.has_mfa);
    }

    #[test]
    fn graphql_detection() {
        let resp = make_response(200, vec![("Content-Type", "application/graphql+json")], "");

        let fp = analyze_response(&resp);

        assert!(fp.has_graphql);
    }

    #[test]
    fn grpc_detection() {
        let resp = make_response(
            200,
            vec![("Content-Type", "application/grpc"), ("grpc-status", "0")],
            "",
        );

        let fp = analyze_response(&resp);

        assert!(fp.has_grpc);
    }

    #[test]
    fn merge_fingerprints() {
        let mut base = Fingerprint {
            server: Some(WebServer::Nginx),
            has_graphql: true,
            ..Default::default()
        };

        let other = Fingerprint {
            server: Some(WebServer::Apache),
            backend: Some(Backend::Django),
            has_websocket: true,
            ..Default::default()
        };

        merge(&mut base, &other);

        assert!(matches!(base.server, Some(WebServer::Nginx)));
        assert!(matches!(base.backend, Some(Backend::Django)));
        assert!(base.has_graphql);
        assert!(base.has_websocket);
    }

    #[test]
    fn merge_detected_technologies_dedup() {
        let mut base = Fingerprint::default();
        base.detected_technologies.push(DetectedTechnology {
            name: "nginx".into(),
            version: None,
            category: TechCategory::Server,
            confidence: 1.0,
        });

        let mut other = Fingerprint::default();
        other.detected_technologies.push(DetectedTechnology {
            name: "nginx".into(),
            version: Some("1.22".into()),
            category: TechCategory::Server,
            confidence: 1.0,
        });
        other.detected_technologies.push(DetectedTechnology {
            name: "React".into(),
            version: None,
            category: TechCategory::JsFramework,
            confidence: 0.9,
        });

        merge(&mut base, &other);

        assert_eq!(base.detected_technologies.len(), 2);
    }

    #[test]
    fn empty_response_produces_defaults() {
        let resp = make_response(200, vec![], "");
        let fp = analyze_response(&resp);

        assert!(fp.server.is_none());
        assert!(fp.backend.is_none());
        assert!(fp.frontend.is_none());
        assert!(fp.cms.is_none());
        assert!(fp.waf.is_none());
        assert!(fp.database.is_none());
        assert!(fp.cdn.is_none());
        assert!(fp.auth_type.is_none());
        assert!(!fp.has_graphql);
        assert!(!fp.has_grpc);
        assert!(!fp.has_websocket);
        assert!(!fp.has_openapi_spec);
        assert!(!fp.has_mfa);
        assert!(!fp.supports_h3);
        assert_eq!(fp.http_version, Some(HttpVersion::Http11));
    }
}
