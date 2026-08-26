use crate::technology::Backend;

use crate::util;

pub struct BackendDetection {
    pub backend: Backend,
    pub version: Option<String>,
    pub confidence: f64,
}

pub fn detect_backend(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<BackendDetection> {
    if let Some(result) = detect_from_powered_by(headers) {
        return Some(result);
    }
    if let Some(result) = detect_from_framework_headers(headers) {
        return Some(result);
    }
    if let Some(result) = detect_from_cookies(headers) {
        return Some(result);
    }
    detect_from_body(body)
}

#[allow(clippy::too_many_lines)]
fn detect_from_powered_by(headers: &[(String, String)]) -> Option<BackendDetection> {
    let value = util::header_value(headers, "x-powered-by")?;
    let lower = value.to_lowercase();

    if lower.contains("express") {
        return Some(BackendDetection {
            backend: Backend::Express,
            version: util::extract_version(value, "Express/"),
            confidence: 1.0,
        });
    }

    if lower.contains("next.js") {
        return Some(BackendDetection {
            backend: Backend::NextJs,
            version: util::extract_version(value, "Next.js/")
                .or_else(|| util::extract_version(value, "Next.js ")),
            confidence: 1.0,
        });
    }

    if lower.contains("nuxt") {
        return Some(BackendDetection {
            backend: Backend::NuxtJs,
            version: None,
            confidence: 1.0,
        });
    }

    if lower.contains("asp.net core") || lower.contains("aspnetcore") {
        return Some(BackendDetection {
            backend: Backend::AspNetCore,
            version: None,
            confidence: 1.0,
        });
    }

    if lower.contains("asp.net") || lower.contains("aspnet") {
        return Some(BackendDetection {
            backend: Backend::AspNet,
            version: None,
            confidence: 1.0,
        });
    }

    if lower.contains("django") {
        return Some(BackendDetection {
            backend: Backend::Django,
            version: None,
            confidence: 1.0,
        });
    }

    if lower.contains("flask") {
        return Some(BackendDetection {
            backend: Backend::Flask,
            version: None,
            confidence: 1.0,
        });
    }

    if lower.contains("laravel") {
        return Some(BackendDetection {
            backend: Backend::Laravel,
            version: None,
            confidence: 0.9,
        });
    }

    if lower.contains("phusion passenger") {
        return Some(BackendDetection {
            backend: Backend::Rails,
            version: None,
            confidence: 0.7,
        });
    }

    None
}

fn detect_from_framework_headers(headers: &[(String, String)]) -> Option<BackendDetection> {
    if util::has_header(headers, "x-django-debug") {
        return Some(BackendDetection {
            backend: Backend::Django,
            version: None,
            confidence: 1.0,
        });
    }

    if util::header_contains(headers, "x-application-context", "application") {
        return Some(BackendDetection {
            backend: Backend::SpringBoot,
            version: None,
            confidence: 0.8,
        });
    }

    if util::has_header(headers, "x-laravel-cache") {
        return Some(BackendDetection {
            backend: Backend::Laravel,
            version: None,
            confidence: 1.0,
        });
    }

    if util::has_header(headers, "x-nextjs-cache")
        || util::has_header(headers, "x-nextjs-matched-path")
    {
        return Some(BackendDetection {
            backend: Backend::NextJs,
            version: None,
            confidence: 1.0,
        });
    }

    if util::header_contains(headers, "server", "cowboy") {
        return Some(BackendDetection {
            backend: Backend::Phoenix,
            version: None,
            confidence: 0.6,
        });
    }

    None
}

#[allow(clippy::too_many_lines)]
fn detect_from_cookies(headers: &[(String, String)]) -> Option<BackendDetection> {
    if util::has_cookie_name(headers, "csrftoken") || util::has_cookie_name(headers, "django_") {
        return Some(BackendDetection {
            backend: Backend::Django,
            version: None,
            confidence: 0.9,
        });
    }

    if util::has_cookie_name(headers, "laravel_session") {
        return Some(BackendDetection {
            backend: Backend::Laravel,
            version: None,
            confidence: 0.95,
        });
    }

    if util::has_cookie_name(headers, "JSESSIONID") {
        return Some(BackendDetection {
            backend: Backend::Spring,
            version: None,
            confidence: 0.7,
        });
    }

    if util::has_cookie_name(headers, "connect.sid") {
        return Some(BackendDetection {
            backend: Backend::Express,
            version: None,
            confidence: 0.8,
        });
    }

    if util::has_cookie_name(headers, ".AspNetCore.") {
        return Some(BackendDetection {
            backend: Backend::AspNetCore,
            version: None,
            confidence: 0.9,
        });
    }

    if util::has_cookie_name(headers, "ASP.NET_SessionId") {
        return Some(BackendDetection {
            backend: Backend::AspNet,
            version: None,
            confidence: 0.8,
        });
    }

    if util::has_cookie_name(headers, "SYMFONY_SESSION")
        || util::has_cookie_name(headers, "sf_redirect")
    {
        return Some(BackendDetection {
            backend: Backend::Symfony,
            version: None,
            confidence: 0.9,
        });
    }

    if util::has_cookie_name(headers, "_rails_session")
        || util::has_cookie_name(headers, "_session_id")
    {
        return Some(BackendDetection {
            backend: Backend::Rails,
            version: None,
            confidence: 0.7,
        });
    }

    None
}

#[allow(clippy::too_many_lines)]
fn detect_from_body(body: Option<&str>) -> Option<BackendDetection> {
    let text = util::body_str(body);
    if text.is_empty() {
        return None;
    }
    let lower = text.to_lowercase();

    if lower.contains("django") && (lower.contains("debug") || lower.contains("traceback")) {
        return Some(BackendDetection {
            backend: Backend::Django,
            version: None,
            confidence: 0.8,
        });
    }

    if lower.contains("/admin/login/") && lower.contains("csrfmiddlewaretoken") {
        return Some(BackendDetection {
            backend: Backend::Django,
            version: None,
            confidence: 0.9,
        });
    }

    if lower.contains("action_controller::routingerror")
        || lower.contains("actioncontroller::routingerror")
    {
        return Some(BackendDetection {
            backend: Backend::Rails,
            version: None,
            confidence: 0.9,
        });
    }

    if text.contains("csrf-token") && text.contains("csrf-param") {
        return Some(BackendDetection {
            backend: Backend::Rails,
            version: None,
            confidence: 0.7,
        });
    }

    if lower.contains("whitelabel error page") || lower.contains("spring boot") {
        return Some(BackendDetection {
            backend: Backend::SpringBoot,
            version: None,
            confidence: 0.9,
        });
    }

    if lower.contains("laravel") && (lower.contains("exception") || lower.contains("symfony\\")) {
        return Some(BackendDetection {
            backend: Backend::Laravel,
            version: None,
            confidence: 0.8,
        });
    }

    if text.contains("__NEXT_DATA__") || text.contains("/_next/") {
        return Some(BackendDetection {
            backend: Backend::NextJs,
            version: None,
            confidence: 0.9,
        });
    }

    if text.contains("__NUXT__") || text.contains("/_nuxt/") {
        return Some(BackendDetection {
            backend: Backend::NuxtJs,
            version: None,
            confidence: 0.9,
        });
    }

    if lower.contains("werkzeug") || (lower.contains("flask") && lower.contains("debugger")) {
        return Some(BackendDetection {
            backend: Backend::Flask,
            version: None,
            confidence: 0.9,
        });
    }

    if lower.contains("fastapi") {
        return Some(BackendDetection {
            backend: Backend::FastApi,
            version: None,
            confidence: 0.8,
        });
    }

    if text.contains("__VIEWSTATE") || text.contains("__EVENTVALIDATION") {
        return Some(BackendDetection {
            backend: Backend::AspNet,
            version: None,
            confidence: 0.9,
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
    fn detect_express_from_powered_by() {
        let headers = h(&[("X-Powered-By", "Express")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::Express));
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn detect_nextjs_from_powered_by() {
        let headers = h(&[("X-Powered-By", "Next.js")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::NextJs));
    }

    #[test]
    fn detect_aspnet_from_powered_by() {
        let headers = h(&[("X-Powered-By", "ASP.NET")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::AspNet));
    }

    #[test]
    fn detect_aspnet_core_from_powered_by() {
        let headers = h(&[("X-Powered-By", "ASP.NET Core")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::AspNetCore));
    }

    #[test]
    fn detect_django_from_cookie() {
        let headers = h(&[("Set-Cookie", "csrftoken=abc123; Path=/")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::Django));
    }

    #[test]
    fn detect_laravel_from_cookie() {
        let headers = h(&[("Set-Cookie", "laravel_session=xyz; Path=/")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::Laravel));
    }

    #[test]
    fn detect_spring_from_cookie() {
        let headers = h(&[("Set-Cookie", "JSESSIONID=abc; Path=/")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::Spring));
    }

    #[test]
    fn detect_express_from_cookie() {
        let headers = h(&[("Set-Cookie", "connect.sid=s%3Aabc; Path=/")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::Express));
    }

    #[test]
    fn detect_nextjs_from_body() {
        let b = Some(r#"<div id="__next"><script id="__NEXT_DATA__">{"props":{}}</script></div>"#);
        let result = detect_backend(&[], b).unwrap();
        assert!(matches!(result.backend, Backend::NextJs));
    }

    #[test]
    fn detect_spring_boot_from_error_page() {
        let b = Some("Whitelabel Error Page - application has no explicit mapping");
        let result = detect_backend(&[], b).unwrap();
        assert!(matches!(result.backend, Backend::SpringBoot));
    }

    #[test]
    fn detect_rails_from_error() {
        let b = Some("ActionController::RoutingError (No route matches)");
        let result = detect_backend(&[], b).unwrap();
        assert!(matches!(result.backend, Backend::Rails));
    }

    #[test]
    fn detect_flask_from_debugger() {
        let b = Some("Werkzeug Debugger - Traceback (most recent call last)");
        let result = detect_backend(&[], b).unwrap();
        assert!(matches!(result.backend, Backend::Flask));
    }

    #[test]
    fn detect_aspnet_from_viewstate() {
        let b = Some(r#"<input type="hidden" name="__VIEWSTATE" value="abc"/>"#);
        let result = detect_backend(&[], b).unwrap();
        assert!(matches!(result.backend, Backend::AspNet));
    }

    #[test]
    fn detect_django_framework_header() {
        let headers = h(&[("X-Django-Debug", "true")]);
        let result = detect_backend(&headers, None).unwrap();
        assert!(matches!(result.backend, Backend::Django));
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn no_backend_detected() {
        let headers = h(&[("Content-Type", "text/html")]);
        assert!(detect_backend(&headers, None).is_none());
    }
}
