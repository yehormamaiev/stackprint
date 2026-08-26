use crate::technology::AuthType;

use crate::util;

pub fn detect_auth_type(headers: &[(String, String)], body: Option<&str>) -> Option<AuthType> {
    if let Some(auth) = detect_from_www_authenticate(headers) {
        return Some(auth);
    }
    if let Some(auth) = detect_from_response_headers(headers) {
        return Some(auth);
    }
    if let Some(auth) = detect_from_cookies(headers) {
        return Some(auth);
    }
    detect_from_body(body)
}

fn detect_from_www_authenticate(headers: &[(String, String)]) -> Option<AuthType> {
    let value = util::header_value(headers, "www-authenticate")?;
    let lower = value.to_lowercase();

    if lower.starts_with("basic") {
        return Some(AuthType::BasicAuth);
    }
    if lower.starts_with("bearer") {
        return Some(AuthType::BearerToken);
    }
    if lower.starts_with("negotiate") || lower.starts_with("ntlm") {
        return Some(AuthType::Certificate);
    }

    None
}

fn detect_from_response_headers(headers: &[(String, String)]) -> Option<AuthType> {
    if util::has_header(headers, "x-oauth-scopes")
        || util::has_header(headers, "x-accepted-oauth-scopes")
    {
        return Some(AuthType::OAuth);
    }

    if util::has_header(headers, "x-api-key") {
        return Some(AuthType::ApiKey);
    }

    None
}

fn detect_from_cookies(headers: &[(String, String)]) -> Option<AuthType> {
    let cookies = util::cookie_values(headers);

    for cookie in &cookies {
        if contains_jwt_pattern(cookie) {
            return Some(AuthType::JWT);
        }

        let lower = cookie.to_lowercase();

        if lower.contains("oauth_token") || lower.contains("access_token=") {
            return Some(AuthType::OAuth);
        }

        if lower.contains("samlsession") || lower.contains("saml_") {
            return Some(AuthType::SAML);
        }

        if lower.contains("api_key=") || lower.contains("apikey=") {
            return Some(AuthType::ApiKey);
        }
    }

    if util::has_cookie_name(headers, "PHPSESSID")
        || util::has_cookie_name(headers, "JSESSIONID")
        || util::has_cookie_name(headers, "connect.sid")
        || util::has_cookie_name(headers, "ASP.NET_SessionId")
    {
        return Some(AuthType::Session);
    }

    None
}

fn contains_jwt_pattern(cookie: &str) -> bool {
    let value = cookie
        .split('=')
        .nth(1)
        .unwrap_or(cookie)
        .split(';')
        .next()
        .unwrap_or("")
        .trim();

    if value.starts_with("eyJ") {
        let parts: Vec<&str> = value.split('.').collect();
        return parts.len() == 3 && parts[1].starts_with("eyJ");
    }

    false
}

fn detect_from_body(body: Option<&str>) -> Option<AuthType> {
    let text = util::body_str(body);
    if text.is_empty() {
        return None;
    }
    let lower = text.to_lowercase();

    if lower.contains("samlrequest") || lower.contains("samlresponse") {
        return Some(AuthType::SAML);
    }

    if lower.contains("oauth") && (lower.contains("authorize") || lower.contains("redirect_uri")) {
        return Some(AuthType::OAuth);
    }

    if text.contains("\"access_token\"") || text.contains("\"id_token\"") {
        return Some(AuthType::JWT);
    }

    None
}

pub fn detect_mfa(headers: &[(String, String)], body: Option<&str>) -> bool {
    if util::has_header(headers, "x-github-otp") || util::has_header(headers, "x-otp-required") {
        return true;
    }

    let text = util::body_str(body);
    if text.is_empty() {
        return false;
    }
    let lower = text.to_lowercase();

    lower.contains("two-factor")
        || lower.contains("2fa")
        || lower.contains("multi-factor")
        || lower.contains("totp")
        || lower.contains("authenticator app")
        || lower.contains("verification code")
        || lower.contains("security key")
        || lower.contains("one-time password")
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
    fn detect_basic_auth() {
        let headers = h(&[("WWW-Authenticate", "Basic realm=\"example\"")]);
        assert_eq!(detect_auth_type(&headers, None), Some(AuthType::BasicAuth));
    }

    #[test]
    fn detect_bearer_auth() {
        let headers = h(&[("WWW-Authenticate", "Bearer realm=\"api\"")]);
        assert_eq!(
            detect_auth_type(&headers, None),
            Some(AuthType::BearerToken)
        );
    }

    #[test]
    fn detect_oauth_from_headers() {
        let headers = h(&[("X-OAuth-Scopes", "repo, user")]);
        assert_eq!(detect_auth_type(&headers, None), Some(AuthType::OAuth));
    }

    #[test]
    fn detect_api_key() {
        let headers = h(&[("X-API-Key", "required")]);
        assert_eq!(detect_auth_type(&headers, None), Some(AuthType::ApiKey));
    }

    #[test]
    fn detect_jwt_from_cookie() {
        let headers = h(&[(
            "Set-Cookie",
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature; Path=/",
        )]);
        assert_eq!(detect_auth_type(&headers, None), Some(AuthType::JWT));
    }

    #[test]
    fn detect_session_from_cookie() {
        let headers = h(&[("Set-Cookie", "PHPSESSID=abc123; Path=/")]);
        assert_eq!(detect_auth_type(&headers, None), Some(AuthType::Session));
    }

    #[test]
    fn detect_saml_from_body() {
        let b = Some(r#"<input type="hidden" name="SAMLResponse" value="abc" />"#);
        assert_eq!(detect_auth_type(&[], b), Some(AuthType::SAML));
    }

    #[test]
    fn detect_oauth_from_body() {
        let b = Some(
            r#"<a href="/oauth/authorize?redirect_uri=https://example.com/callback">Login</a>"#,
        );
        assert_eq!(detect_auth_type(&[], b), Some(AuthType::OAuth));
    }

    #[test]
    fn detect_jwt_from_body() {
        let b = Some(r#"{"access_token": "eyJhbGciOiJ..."}"#);
        assert_eq!(detect_auth_type(&[], b), Some(AuthType::JWT));
    }

    #[test]
    fn mfa_detected_from_body() {
        let b = Some("Enter your two-factor authentication code");
        assert!(detect_mfa(&[], b));
    }

    #[test]
    fn mfa_detected_from_totp() {
        let b = Some("Configure your TOTP authenticator app");
        assert!(detect_mfa(&[], b));
    }

    #[test]
    fn mfa_detected_from_header() {
        let headers = h(&[("X-GitHub-OTP", "required; app")]);
        assert!(detect_mfa(&headers, None));
    }

    #[test]
    fn no_mfa() {
        let b = Some("<html><body>Normal login</body></html>");
        assert!(!detect_mfa(&[], b));
    }

    #[test]
    fn jwt_pattern_valid() {
        assert!(contains_jwt_pattern(
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        ));
    }

    #[test]
    fn jwt_pattern_invalid() {
        assert!(!contains_jwt_pattern("session=abc123"));
        assert!(!contains_jwt_pattern("token=eyJhbG.notjwt"));
    }

    #[test]
    fn no_auth_detected() {
        let headers = h(&[("Content-Type", "text/html")]);
        assert!(detect_auth_type(&headers, None).is_none());
    }
}
