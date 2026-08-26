use crate::util;

pub fn detect_h3_support(headers: &[(String, String)]) -> bool {
    util::header_value(headers, "alt-svc").is_some_and(|alt_svc| {
        let lower = alt_svc.to_lowercase();
        lower.contains("h3=") || lower.contains("h3-")
    })
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
    fn h3_from_alt_svc() {
        let headers = h(&[("Alt-Svc", r#"h3=":443"; ma=86400"#)]);
        assert!(detect_h3_support(&headers));
    }

    #[test]
    fn h3_draft_version() {
        let headers = h(&[("Alt-Svc", r#"h3-29=":443""#)]);
        assert!(detect_h3_support(&headers));
    }

    #[test]
    fn no_h3_support() {
        let headers = h(&[("Alt-Svc", r#"h2=":443""#)]);
        assert!(!detect_h3_support(&headers));
    }

    #[test]
    fn no_alt_svc_header() {
        let headers = h(&[("Server", "nginx")]);
        assert!(!detect_h3_support(&headers));
    }

    #[test]
    fn h3_combined_alt_svc() {
        let headers = h(&[("Alt-Svc", r#"h2=":443"; h3=":443"; ma=86400"#)]);
        assert!(detect_h3_support(&headers));
    }
}
