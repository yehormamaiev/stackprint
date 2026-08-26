pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

pub fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

pub fn header_contains(headers: &[(String, String)], name: &str, needle: &str) -> bool {
    let lower_needle = needle.to_lowercase();
    header_value(headers, name).is_some_and(|v| v.to_lowercase().contains(&lower_needle))
}

pub fn any_header_value_contains(headers: &[(String, String)], needle: &str) -> bool {
    let lower_needle = needle.to_lowercase();
    headers
        .iter()
        .any(|(_, v)| v.to_lowercase().contains(&lower_needle))
}

pub fn cookie_values(headers: &[(String, String)]) -> Vec<&str> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie") || k.eq_ignore_ascii_case("cookie"))
        .map(|(_, v)| v.as_str())
        .collect()
}

pub fn has_cookie_name(headers: &[(String, String)], name: &str) -> bool {
    let lower = name.to_lowercase();
    cookie_values(headers)
        .iter()
        .any(|c| c.to_lowercase().contains(&lower))
}

pub fn extract_version(text: &str, prefix: &str) -> Option<String> {
    let lower_text = text.to_lowercase();
    let lower_prefix = prefix.to_lowercase();
    let idx = lower_text.find(&lower_prefix)?;
    let after = &text[idx + prefix.len()..];
    let version: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let trimmed = version.trim_end_matches('.');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn body_str(body: Option<&str>) -> &str {
    body.unwrap_or("")
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
    fn header_value_case_insensitive() {
        let headers = h(&[("Content-Type", "text/html"), ("Server", "nginx")]);
        assert_eq!(header_value(&headers, "content-type"), Some("text/html"));
        assert_eq!(header_value(&headers, "SERVER"), Some("nginx"));
        assert_eq!(header_value(&headers, "x-missing"), None);
    }

    #[test]
    fn multiple_header_values() {
        let headers = h(&[
            ("Set-Cookie", "a=1"),
            ("Set-Cookie", "b=2"),
            ("Content-Type", "text/html"),
        ]);
        let cookies = header_values(&headers, "set-cookie");
        assert_eq!(cookies.len(), 2);
    }

    #[test]
    fn has_header_works() {
        let headers = h(&[("X-Custom", "value")]);
        assert!(has_header(&headers, "x-custom"));
        assert!(!has_header(&headers, "x-missing"));
    }

    #[test]
    fn header_contains_works() {
        let headers = h(&[("Server", "Apache/2.4.52")]);
        assert!(header_contains(&headers, "server", "apache"));
        assert!(!header_contains(&headers, "server", "nginx"));
    }

    #[test]
    fn cookie_name_detection() {
        let headers = h(&[
            ("Set-Cookie", "JSESSIONID=abc123; Path=/"),
            ("Set-Cookie", "csrftoken=xyz; HttpOnly"),
        ]);
        assert!(has_cookie_name(&headers, "JSESSIONID"));
        assert!(has_cookie_name(&headers, "csrftoken"));
        assert!(!has_cookie_name(&headers, "laravel_session"));
    }

    #[test]
    fn version_extraction() {
        assert_eq!(
            extract_version("Apache/2.4.52 (Ubuntu)", "Apache/"),
            Some("2.4.52".into())
        );
        assert_eq!(
            extract_version("nginx/1.22.1", "nginx/"),
            Some("1.22.1".into())
        );
        assert_eq!(
            extract_version("Microsoft-IIS/10.0", "Microsoft-IIS/"),
            Some("10.0".into())
        );
        assert_eq!(extract_version("ServerName", "ServerName/"), None);
    }

    #[test]
    fn body_str_works() {
        let body = Some("Hello World".to_string());
        assert_eq!(body_str(body.as_deref()), "Hello World");
        assert_eq!(body_str(None), "");
    }

    #[test]
    fn any_header_value_search() {
        let headers = h(&[("Server", "nginx"), ("X-Powered-By", "Express")]);
        assert!(any_header_value_contains(&headers, "express"));
        assert!(!any_header_value_contains(&headers, "django"));
    }
}
