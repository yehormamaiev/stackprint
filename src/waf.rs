use crate::technology::Waf;

use crate::util;

pub struct WafDetection {
    pub waf: Waf,
    pub confidence: f64,
}

pub fn detect_waf(headers: &[(String, String)], body: Option<&str>) -> Option<WafDetection> {
    if let Some(result) = detect_from_headers(headers) {
        return Some(result);
    }
    if let Some(result) = detect_from_cookies(headers) {
        return Some(result);
    }
    detect_from_body(body)
}

#[allow(clippy::too_many_lines)]
fn detect_from_headers(headers: &[(String, String)]) -> Option<WafDetection> {
    if util::has_header(headers, "cf-ray") || util::has_header(headers, "cf-cache-status") {
        return Some(WafDetection {
            waf: Waf::Cloudflare,
            confidence: 1.0,
        });
    }

    if util::has_header(headers, "x-sucuri-id") || util::has_header(headers, "x-sucuri-cache") {
        return Some(WafDetection {
            waf: Waf::Sucuri,
            confidence: 1.0,
        });
    }

    if util::has_header(headers, "x-akamai-transformed")
        || util::header_contains(headers, "server", "akamaighost")
    {
        return Some(WafDetection {
            waf: Waf::Akamai,
            confidence: 1.0,
        });
    }

    if util::has_header(headers, "x-amzn-waf-action") {
        return Some(WafDetection {
            waf: Waf::AwsWaf,
            confidence: 1.0,
        });
    }

    if util::has_header(headers, "x-iinfo") || util::header_contains(headers, "server", "incapsula")
    {
        return Some(WafDetection {
            waf: Waf::Imperva,
            confidence: 1.0,
        });
    }

    if util::header_contains(headers, "server", "bigip")
        || util::header_contains(headers, "server", "big-ip")
    {
        return Some(WafDetection {
            waf: Waf::F5BigIp,
            confidence: 1.0,
        });
    }

    if util::header_contains(headers, "server", "barracuda") {
        return Some(WafDetection {
            waf: Waf::Barracuda,
            confidence: 1.0,
        });
    }

    if util::has_header(headers, "fortiwafsid")
        || util::header_contains(headers, "server", "fortiweb")
    {
        return Some(WafDetection {
            waf: Waf::Fortinet,
            confidence: 1.0,
        });
    }

    if util::header_contains(headers, "server", "mod_security")
        || util::header_contains(headers, "server", "modsecurity")
    {
        return Some(WafDetection {
            waf: Waf::ModSecurity,
            confidence: 1.0,
        });
    }

    None
}

fn detect_from_cookies(headers: &[(String, String)]) -> Option<WafDetection> {
    let cookies = util::cookie_values(headers);

    for cookie in &cookies {
        let lower = cookie.to_lowercase();

        if lower.contains("__cfduid") || lower.contains("cf_clearance") || lower.contains("__cf_bm")
        {
            return Some(WafDetection {
                waf: Waf::Cloudflare,
                confidence: 0.9,
            });
        }

        if lower.contains("incap_ses_") || lower.contains("visid_incap_") {
            return Some(WafDetection {
                waf: Waf::Imperva,
                confidence: 0.9,
            });
        }

        if lower.contains("sucuri_cloudproxy_") {
            return Some(WafDetection {
                waf: Waf::Sucuri,
                confidence: 0.9,
            });
        }

        if lower.contains("bigipserver") {
            return Some(WafDetection {
                waf: Waf::F5BigIp,
                confidence: 0.9,
            });
        }

        if lower.contains("barra_counter_session") {
            return Some(WafDetection {
                waf: Waf::Barracuda,
                confidence: 0.9,
            });
        }
    }

    None
}

fn detect_from_body(body: Option<&str>) -> Option<WafDetection> {
    let text = util::body_str(body);
    if text.is_empty() {
        return None;
    }
    let lower = text.to_lowercase();

    if lower.contains("attention required! | cloudflare")
        || lower.contains("cloudflare ray id")
        || lower.contains("performance & security by cloudflare")
    {
        return Some(WafDetection {
            waf: Waf::Cloudflare,
            confidence: 0.9,
        });
    }

    if lower.contains("incapsula incident id") || lower.contains("powered by incapsula") {
        return Some(WafDetection {
            waf: Waf::Imperva,
            confidence: 0.9,
        });
    }

    if lower.contains("sucuri website firewall") || lower.contains("access denied - sucuri") {
        return Some(WafDetection {
            waf: Waf::Sucuri,
            confidence: 0.9,
        });
    }

    if lower.contains("mod_security") || lower.contains("modsecurity") {
        return Some(WafDetection {
            waf: Waf::ModSecurity,
            confidence: 0.8,
        });
    }

    if lower.contains("aws waf") || (lower.contains("request blocked") && lower.contains("aws")) {
        return Some(WafDetection {
            waf: Waf::AwsWaf,
            confidence: 0.8,
        });
    }

    if lower.contains("akamai") && (lower.contains("access denied") || lower.contains("reference#"))
    {
        return Some(WafDetection {
            waf: Waf::Akamai,
            confidence: 0.8,
        });
    }

    if lower.contains("the requested url was rejected") && lower.contains("support id") {
        return Some(WafDetection {
            waf: Waf::F5BigIp,
            confidence: 0.7,
        });
    }

    if lower.contains("barracuda") && lower.contains("web application firewall") {
        return Some(WafDetection {
            waf: Waf::Barracuda,
            confidence: 0.8,
        });
    }

    if lower.contains("fortiguard") || lower.contains("fortiweb") {
        return Some(WafDetection {
            waf: Waf::Fortinet,
            confidence: 0.8,
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
    fn detect_cloudflare_from_headers() {
        let headers = h(&[("cf-ray", "abc123"), ("Server", "cloudflare")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::Cloudflare));
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn detect_cloudflare_from_cookies() {
        let headers = h(&[("Set-Cookie", "__cf_bm=abc; Path=/")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::Cloudflare));
        assert_eq!(result.confidence, 0.9);
    }

    #[test]
    fn detect_cloudflare_from_body() {
        let b = Some("Cloudflare Ray ID: 1234567890");
        let result = detect_waf(&[], b).unwrap();
        assert!(matches!(result.waf, Waf::Cloudflare));
    }

    #[test]
    fn detect_imperva_from_headers() {
        let headers = h(&[("X-Iinfo", "123-456")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::Imperva));
    }

    #[test]
    fn detect_imperva_from_cookies() {
        let headers = h(&[("Set-Cookie", "visid_incap_123=abc")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::Imperva));
    }

    #[test]
    fn detect_aws_waf() {
        let headers = h(&[("x-amzn-waf-action", "block")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::AwsWaf));
    }

    #[test]
    fn detect_akamai() {
        let headers = h(&[("X-Akamai-Transformed", "9c 12345")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::Akamai));
    }

    #[test]
    fn detect_f5_bigip() {
        let headers = h(&[("Server", "BigIP")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::F5BigIp));
    }

    #[test]
    fn detect_modsecurity_from_body() {
        let b = Some("ModSecurity: Access denied with code 403");
        let result = detect_waf(&[], b).unwrap();
        assert!(matches!(result.waf, Waf::ModSecurity));
    }

    #[test]
    fn detect_sucuri() {
        let headers = h(&[("X-Sucuri-ID", "12345")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::Sucuri));
    }

    #[test]
    fn detect_fortinet() {
        let headers = h(&[("fortiwafsid", "session123")]);
        let result = detect_waf(&headers, None).unwrap();
        assert!(matches!(result.waf, Waf::Fortinet));
    }

    #[test]
    fn no_waf_detected() {
        let headers = h(&[("Server", "nginx"), ("Content-Type", "text/html")]);
        assert!(detect_waf(&headers, None).is_none());
    }
}
