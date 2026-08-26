use crate::technology::WebServer;

use crate::util;

pub struct ServerDetection {
    pub server: WebServer,
    pub version: Option<String>,
    pub confidence: f64,
}

pub fn detect_server(headers: &[(String, String)]) -> Option<ServerDetection> {
    if let Some(result) = detect_from_server_header(headers) {
        return Some(result);
    }
    if let Some(result) = detect_from_powered_by(headers) {
        return Some(result);
    }
    detect_from_via_header(headers)
}

fn detect_from_server_header(headers: &[(String, String)]) -> Option<ServerDetection> {
    let server = util::header_value(headers, "server")?;
    let lower = server.to_lowercase();

    if lower.contains("apache") {
        return Some(ServerDetection {
            server: WebServer::Apache,
            version: util::extract_version(server, "Apache/"),
            confidence: 1.0,
        });
    }

    if lower.contains("nginx") {
        return Some(ServerDetection {
            server: WebServer::Nginx,
            version: util::extract_version(server, "nginx/"),
            confidence: 1.0,
        });
    }

    if lower.contains("microsoft-iis") || lower.contains("iis/") {
        return Some(ServerDetection {
            server: WebServer::Iis,
            version: util::extract_version(server, "Microsoft-IIS/")
                .or_else(|| util::extract_version(server, "IIS/")),
            confidence: 1.0,
        });
    }

    if lower.contains("litespeed") {
        return Some(ServerDetection {
            server: WebServer::LiteSpeed,
            version: util::extract_version(server, "LiteSpeed/"),
            confidence: 1.0,
        });
    }

    if lower.contains("caddy") {
        return Some(ServerDetection {
            server: WebServer::Caddy,
            version: util::extract_version(server, "Caddy/"),
            confidence: 1.0,
        });
    }

    if lower.contains("envoy") {
        return Some(ServerDetection {
            server: WebServer::Envoy,
            version: util::extract_version(server, "envoy/"),
            confidence: 1.0,
        });
    }

    if lower.contains("traefik") {
        return Some(ServerDetection {
            server: WebServer::Traefik,
            version: util::extract_version(server, "Traefik/"),
            confidence: 1.0,
        });
    }

    if !server.is_empty() {
        return Some(ServerDetection {
            server: WebServer::Other(server.to_string()),
            version: None,
            confidence: 0.5,
        });
    }

    None
}

fn detect_from_powered_by(headers: &[(String, String)]) -> Option<ServerDetection> {
    let powered_by = util::header_value(headers, "x-powered-by")?;
    let lower = powered_by.to_lowercase();

    if lower.contains("asp.net") || lower.contains("aspnet") {
        return Some(ServerDetection {
            server: WebServer::Iis,
            version: None,
            confidence: 0.7,
        });
    }

    None
}

fn detect_from_via_header(headers: &[(String, String)]) -> Option<ServerDetection> {
    let via = util::header_value(headers, "via")?;
    let lower = via.to_lowercase();

    if lower.contains("nginx") {
        return Some(ServerDetection {
            server: WebServer::Nginx,
            version: util::extract_version(via, "nginx/"),
            confidence: 0.5,
        });
    }

    if lower.contains("apache") {
        return Some(ServerDetection {
            server: WebServer::Apache,
            version: None,
            confidence: 0.5,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn detect_apache() {
        let headers = h(&[("Server", "Apache/2.4.52 (Ubuntu)")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Apache));
        assert_eq!(result.version, Some("2.4.52".into()));
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn detect_nginx() {
        let headers = h(&[("Server", "nginx/1.22.1")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Nginx));
        assert_eq!(result.version, Some("1.22.1".into()));
    }

    #[test]
    fn detect_iis() {
        let headers = h(&[("Server", "Microsoft-IIS/10.0")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Iis));
        assert_eq!(result.version, Some("10.0".into()));
    }

    #[test]
    fn detect_iis_from_aspnet() {
        let headers = h(&[("X-Powered-By", "ASP.NET")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Iis));
        assert_eq!(result.confidence, 0.7);
    }

    #[test]
    fn detect_litespeed() {
        let headers = h(&[("Server", "LiteSpeed/5.4")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::LiteSpeed));
        assert_eq!(result.version, Some("5.4".into()));
    }

    #[test]
    fn detect_caddy() {
        let headers = h(&[("Server", "Caddy")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Caddy));
    }

    #[test]
    fn detect_envoy() {
        let headers = h(&[("Server", "envoy")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Envoy));
    }

    #[test]
    fn detect_traefik() {
        let headers = h(&[("Server", "Traefik/2.10")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Traefik));
        assert_eq!(result.version, Some("2.10".into()));
    }

    #[test]
    fn detect_from_via() {
        let headers = h(&[("Via", "1.1 nginx/1.20")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Nginx));
        assert_eq!(result.confidence, 0.5);
    }

    #[test]
    fn detect_unknown_server() {
        let headers = h(&[("Server", "CustomServer/3.0")]);
        let result = detect_server(&headers).unwrap();
        assert!(matches!(result.server, WebServer::Other(_)));
    }

    #[test]
    fn no_server_header() {
        let headers = h(&[("Content-Type", "text/html")]);
        assert!(detect_server(&headers).is_none());
    }
}
