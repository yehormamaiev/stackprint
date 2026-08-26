use crate::technology::Cdn;

use crate::util;

pub fn detect_cdn(headers: &[(String, String)]) -> Option<Cdn> {
    if let Some(result) = detect_from_cdn_headers(headers) {
        return Some(result);
    }
    detect_from_x_cdn_header(headers)
}

#[allow(clippy::too_many_lines)]
fn detect_from_cdn_headers(headers: &[(String, String)]) -> Option<Cdn> {
    if util::has_header(headers, "cf-ray") || util::has_header(headers, "cf-cache-status") {
        return Some(Cdn::Cloudflare);
    }

    if util::has_header(headers, "x-fastly-request-id")
        || util::has_header(headers, "fastly-io-info")
        || util::header_contains(headers, "via", "fastly")
    {
        return Some(Cdn::Fastly);
    }

    if util::has_header(headers, "x-akamai-transformed")
        || util::has_header(headers, "x-akamai-request-id")
        || util::header_contains(headers, "server", "akamaighost")
    {
        return Some(Cdn::Akamai);
    }

    if util::has_header(headers, "x-amz-cf-id") || util::has_header(headers, "x-amz-cf-pop") {
        return Some(Cdn::AwsCloudFront);
    }

    if util::has_header(headers, "x-azure-ref") || util::has_header(headers, "x-ms-ref") {
        return Some(Cdn::AzureCdn);
    }

    if util::header_contains(headers, "via", "google")
        || util::has_header(headers, "x-goog-hash")
    {
        return Some(Cdn::GoogleCloud);
    }

    if util::header_contains(headers, "server", "keycdn") {
        return Some(Cdn::KeyCdn);
    }

    if util::has_header(headers, "x-sp-url") || util::has_header(headers, "x-sp-wl") {
        return Some(Cdn::StackPath);
    }

    None
}

fn detect_from_x_cdn_header(headers: &[(String, String)]) -> Option<Cdn> {
    let cdn_header = util::header_value(headers, "x-cdn")?;
    let lower = cdn_header.to_lowercase();

    if lower.contains("cloudflare") {
        return Some(Cdn::Cloudflare);
    }
    if lower.contains("fastly") {
        return Some(Cdn::Fastly);
    }
    if lower.contains("akamai") {
        return Some(Cdn::Akamai);
    }
    if lower.contains("cloudfront") {
        return Some(Cdn::AwsCloudFront);
    }

    Some(Cdn::Other(cdn_header.to_string()))
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
    fn detect_cloudflare() {
        let headers = h(&[("cf-ray", "abc123")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::Cloudflare)));
    }

    #[test]
    fn detect_fastly() {
        let headers = h(&[("x-fastly-request-id", "abc")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::Fastly)));
    }

    #[test]
    fn detect_fastly_via() {
        let headers = h(&[("Via", "1.1 varnish (Fastly)")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::Fastly)));
    }

    #[test]
    fn detect_akamai() {
        let headers = h(&[("X-Akamai-Transformed", "9c 12345")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::Akamai)));
    }

    #[test]
    fn detect_cloudfront() {
        let headers = h(&[("x-amz-cf-id", "abc123")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::AwsCloudFront)));
    }

    #[test]
    fn detect_azure() {
        let headers = h(&[("X-Azure-Ref", "abc")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::AzureCdn)));
    }

    #[test]
    fn detect_google_cloud() {
        let headers = h(&[("X-Goog-Hash", "crc32c=abc")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::GoogleCloud)));
    }

    #[test]
    fn detect_from_x_cdn() {
        let headers = h(&[("X-CDN", "Fastly")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::Fastly)));
    }

    #[test]
    fn detect_stackpath() {
        let headers = h(&[("x-sp-url", "/something")]);
        assert!(matches!(detect_cdn(&headers), Some(Cdn::StackPath)));
    }

    #[test]
    fn no_cdn() {
        let headers = h(&[("Server", "nginx"), ("Content-Type", "text/html")]);
        assert!(detect_cdn(&headers).is_none());
    }
}
