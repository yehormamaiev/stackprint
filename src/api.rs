use crate::util;

pub fn detect_graphql_from_response(headers: &[(String, String)], body: Option<&str>) -> bool {
    if util::header_contains(headers, "content-type", "application/graphql") {
        return true;
    }

    let text = util::body_str(body);
    if text.is_empty() {
        return false;
    }

    if text.contains("graphiql") || text.contains("GraphQL Playground") {
        return true;
    }

    if text.contains("\"data\"") && text.contains("\"errors\"") && text.contains("graphql") {
        return true;
    }

    false
}

pub fn detect_grpc(headers: &[(String, String)]) -> bool {
    util::header_contains(headers, "content-type", "application/grpc")
        || util::has_header(headers, "grpc-status")
        || util::has_header(headers, "grpc-message")
        || util::has_header(headers, "grpc-encoding")
}

pub fn detect_websocket_from_response(headers: &[(String, String)], body: Option<&str>) -> bool {
    if util::header_contains(headers, "upgrade", "websocket") {
        return true;
    }

    let text = util::body_str(body);
    text.contains("new WebSocket(") || text.contains("wss://") || text.contains("ws://")
}

pub fn detect_openapi_from_response(body: Option<&str>) -> bool {
    let text = util::body_str(body);
    if text.is_empty() {
        return false;
    }

    text.contains("\"openapi\"")
        || text.contains("\"swagger\"")
        || text.contains("swagger-ui")
        || text.contains("swagger.json")
        || text.contains("openapi.json")
        || text.contains("redoc standalone")
}

pub const GRAPHQL_PROBE_PATHS: &[&str] = &[
    "/graphql",
    "/graphql/playground",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
];

pub const OPENAPI_PROBE_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/.well-known/openapi",
];

pub const GRAPHQL_INTROSPECTION_QUERY: &str = r#"{"query":"{ __typename }"}"#;

pub fn is_graphql_response(body: Option<&str>) -> bool {
    let text = util::body_str(body);
    (text.contains("\"data\"") && text.contains('{'))
        || text.contains("graphiql")
        || text.contains("GraphQL")
}

pub fn is_openapi_response(body: Option<&str>) -> bool {
    let text = util::body_str(body);
    (text.contains("\"openapi\"") || text.contains("\"swagger\"")) && text.contains("\"paths\"")
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
    fn detect_graphql_from_header() {
        let headers = h(&[("Content-Type", "application/graphql+json")]);
        assert!(detect_graphql_from_response(&headers, None));
    }

    #[test]
    fn detect_graphql_from_body() {
        let b = Some(r"<title>GraphQL Playground</title>");
        assert!(detect_graphql_from_response(&[], b));
    }

    #[test]
    fn detect_graphql_graphiql() {
        let b = Some(r#"<div id="graphiql">Loading GraphiQL...</div>"#);
        assert!(detect_graphql_from_response(&[], b));
    }

    #[test]
    fn detect_grpc_from_headers() {
        let headers = h(&[("Content-Type", "application/grpc")]);
        assert!(detect_grpc(&headers));
    }

    #[test]
    fn detect_grpc_status() {
        let headers = h(&[("grpc-status", "0"), ("grpc-message", "OK")]);
        assert!(detect_grpc(&headers));
    }

    #[test]
    fn detect_websocket_from_header() {
        let headers = h(&[("Upgrade", "websocket")]);
        assert!(detect_websocket_from_response(&headers, None));
    }

    #[test]
    fn detect_websocket_from_body() {
        let b = Some(r#"var ws = new WebSocket("wss://example.com/ws");"#);
        assert!(detect_websocket_from_response(&[], b));
    }

    #[test]
    fn detect_openapi_from_body() {
        let b = Some(r#"<div id="swagger-ui"></div><script src="/swagger.json"></script>"#);
        assert!(detect_openapi_from_response(b));
    }

    #[test]
    fn is_graphql_response_valid() {
        let b = Some(r#"{"data":{"__typename":"Query"}}"#);
        assert!(is_graphql_response(b));
    }

    #[test]
    fn is_openapi_valid() {
        let b = Some(r#"{"openapi":"3.0.0","info":{},"paths":{"/api/users":{}}}"#);
        assert!(is_openapi_response(b));
    }

    #[test]
    fn no_graphql() {
        let b = Some("<html><body>Normal page</body></html>");
        assert!(!detect_graphql_from_response(&[], b));
    }

    #[test]
    fn no_grpc() {
        let headers = h(&[("Content-Type", "text/html")]);
        assert!(!detect_grpc(&headers));
    }

    #[test]
    fn no_websocket() {
        let b = Some("<html>No websockets here</html>");
        assert!(!detect_websocket_from_response(&[], b));
    }
}
