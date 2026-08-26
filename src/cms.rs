use crate::technology::Cms;

use crate::util;

pub struct CmsDetection {
    pub cms: Cms,
    pub version: Option<String>,
    pub confidence: f64,
}

pub fn detect_cms(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<CmsDetection> {
    if let Some(result) = detect_from_meta_generator(body) {
        return Some(result);
    }
    if let Some(result) = detect_from_body_patterns(body) {
        return Some(result);
    }
    detect_from_headers(headers)
}

fn detect_from_meta_generator(body: Option<&str>) -> Option<CmsDetection> {
    let text = util::body_str(body);
    let gen_content = extract_meta_generator(text)?;
    let lower_gen = gen_content.to_lowercase();

    if lower_gen.contains("wordpress") {
        return Some(CmsDetection {
            cms: Cms::WordPress,
            version: util::extract_version(&gen_content, "WordPress "),
            confidence: 1.0,
        });
    }

    if lower_gen.contains("drupal") {
        return Some(CmsDetection {
            cms: Cms::Drupal,
            version: util::extract_version(&gen_content, "Drupal "),
            confidence: 1.0,
        });
    }

    if lower_gen.contains("joomla") {
        return Some(CmsDetection {
            cms: Cms::Joomla,
            version: util::extract_version(&gen_content, "Joomla! "),
            confidence: 1.0,
        });
    }

    if lower_gen.contains("ghost") {
        return Some(CmsDetection {
            cms: Cms::Ghost,
            version: util::extract_version(&gen_content, "Ghost "),
            confidence: 1.0,
        });
    }

    if lower_gen.contains("magento") {
        return Some(CmsDetection {
            cms: Cms::Magento,
            version: None,
            confidence: 1.0,
        });
    }

    None
}

fn extract_meta_generator(body: &str) -> Option<String> {
    let lower = body.to_lowercase();

    let gen_idx = lower
        .find("name=\"generator\"")
        .or_else(|| lower.find("name='generator'"))?;

    let tag_start = lower[..gen_idx].rfind('<')?;
    let tag_end_offset = lower[gen_idx..].find('>')?;
    let tag_end = gen_idx + tag_end_offset;

    let original_tag = &body[tag_start..=tag_end];
    let tag_lower = original_tag.to_lowercase();

    let value_start = if let Some(idx) = tag_lower.find("content=\"") {
        idx + 9
    } else if let Some(idx) = tag_lower.find("content='") {
        idx + 9
    } else {
        return None;
    };

    let quote = if tag_lower.as_bytes().get(value_start.wrapping_sub(1)) == Some(&b'"') {
        '"'
    } else {
        '\''
    };

    let value_end = original_tag[value_start..].find(quote)?;
    Some(original_tag[value_start..value_start + value_end].to_string())
}

#[allow(clippy::too_many_lines)]
fn detect_from_body_patterns(body: Option<&str>) -> Option<CmsDetection> {
    let text = util::body_str(body);
    if text.is_empty() {
        return None;
    }

    if text.contains("/wp-content/") || text.contains("/wp-includes/") {
        return Some(CmsDetection {
            cms: Cms::WordPress,
            version: extract_wp_version(text),
            confidence: 0.95,
        });
    }

    if text.contains("/wp-json/") || text.contains("wp-embed.min.js") {
        return Some(CmsDetection {
            cms: Cms::WordPress,
            version: None,
            confidence: 0.9,
        });
    }

    if text.contains("Drupal.settings") || text.contains("/sites/default/files") {
        return Some(CmsDetection {
            cms: Cms::Drupal,
            version: None,
            confidence: 0.95,
        });
    }

    if text.contains("/core/misc/drupal.js") {
        return Some(CmsDetection {
            cms: Cms::Drupal,
            version: None,
            confidence: 0.8,
        });
    }

    if text.contains("/media/jui/") || text.contains("/media/system/js/") {
        return Some(CmsDetection {
            cms: Cms::Joomla,
            version: None,
            confidence: 0.8,
        });
    }

    if text.contains("ghost-url") || text.contains("content/themes/casper") {
        return Some(CmsDetection {
            cms: Cms::Ghost,
            version: None,
            confidence: 0.85,
        });
    }

    if text.contains("Mage.Cookies") || text.contains("/static/frontend/Magento") {
        return Some(CmsDetection {
            cms: Cms::Magento,
            version: None,
            confidence: 0.85,
        });
    }

    if text.contains("cdn.shopify.com") || text.contains("Shopify.theme") {
        return Some(CmsDetection {
            cms: Cms::Shopify,
            version: None,
            confidence: 0.95,
        });
    }

    None
}

fn extract_wp_version(body: &str) -> Option<String> {
    util::extract_version(body, "WordPress ").or_else(|| {
        let wp_idx = body.find("wp-includes")?;
        let after = &body[wp_idx..];
        let ver_idx = after.find("ver=")?;
        let ver_after = &after[ver_idx + 4..];
        let version: String = ver_after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let trimmed = version.trim_end_matches('.');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn detect_from_headers(headers: &[(String, String)]) -> Option<CmsDetection> {
    if util::header_contains(headers, "link", "wp-json") {
        return Some(CmsDetection {
            cms: Cms::WordPress,
            version: None,
            confidence: 0.9,
        });
    }

    if util::has_header(headers, "x-drupal-cache")
        || util::has_header(headers, "x-generator")
            && util::header_contains(headers, "x-generator", "drupal")
    {
        return Some(CmsDetection {
            cms: Cms::Drupal,
            version: None,
            confidence: 1.0,
        });
    }

    if util::has_header(headers, "x-shopid")
        || util::has_header(headers, "x-shopify-stage")
    {
        return Some(CmsDetection {
            cms: Cms::Shopify,
            version: None,
            confidence: 1.0,
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
    fn detect_wordpress_from_generator() {
        let b = Some(r#"<meta name="generator" content="WordPress 6.5.2" />"#);
        let result = detect_cms(&[], b).unwrap();
        assert!(matches!(result.cms, Cms::WordPress));
        assert_eq!(result.version, Some("6.5.2".into()));
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn detect_wordpress_from_body() {
        let b = Some(r#"<link rel="stylesheet" href="/wp-content/themes/theme/style.css?ver=6.5" />"#);
        let result = detect_cms(&[], b).unwrap();
        assert!(matches!(result.cms, Cms::WordPress));
    }

    #[test]
    fn detect_wordpress_from_header() {
        let headers = h(&[("Link", r#"<https://example.com/wp-json/>; rel="https://api.w.org/""#)]);
        let result = detect_cms(&headers, None).unwrap();
        assert!(matches!(result.cms, Cms::WordPress));
    }

    #[test]
    fn detect_drupal_from_generator() {
        let b = Some(r#"<meta name="generator" content="Drupal 10" />"#);
        let result = detect_cms(&[], b).unwrap();
        assert!(matches!(result.cms, Cms::Drupal));
        assert_eq!(result.version, Some("10".into()));
    }

    #[test]
    fn detect_drupal_from_body() {
        let b = Some(r#"<script>Drupal.settings = {"basePath":"/"};</script>"#);
        let result = detect_cms(&[], b).unwrap();
        assert!(matches!(result.cms, Cms::Drupal));
    }

    #[test]
    fn detect_drupal_from_header() {
        let headers = h(&[("X-Drupal-Cache", "HIT")]);
        let result = detect_cms(&headers, None).unwrap();
        assert!(matches!(result.cms, Cms::Drupal));
    }

    #[test]
    fn detect_joomla() {
        let b = Some(r#"<script src="/media/jui/js/jquery.min.js"></script>"#);
        let result = detect_cms(&[], b).unwrap();
        assert!(matches!(result.cms, Cms::Joomla));
    }

    #[test]
    fn detect_shopify_from_body() {
        let b = Some(r#"<script src="https://cdn.shopify.com/s/files/theme.js"></script>"#);
        let result = detect_cms(&[], b).unwrap();
        assert!(matches!(result.cms, Cms::Shopify));
    }

    #[test]
    fn detect_shopify_from_header() {
        let headers = h(&[("X-ShopId", "12345")]);
        let result = detect_cms(&headers, None).unwrap();
        assert!(matches!(result.cms, Cms::Shopify));
    }

    #[test]
    fn detect_ghost() {
        let b = Some(r#"<meta name="generator" content="Ghost 5.82" />"#);
        let result = detect_cms(&[], b).unwrap();
        assert!(matches!(result.cms, Cms::Ghost));
        assert_eq!(result.version, Some("5.82".into()));
    }

    #[test]
    fn no_cms_detected() {
        let b = Some("<html><body>Simple page</body></html>");
        assert!(detect_cms(&[], b).is_none());
    }

    #[test]
    fn extract_meta_generator_double_quotes() {
        let result = extract_meta_generator(
            r#"<head><meta name="generator" content="WordPress 6.5" /></head>"#,
        );
        assert_eq!(result, Some("WordPress 6.5".into()));
    }

    #[test]
    fn extract_meta_generator_single_quotes() {
        let result = extract_meta_generator(
            "<head><meta name='generator' content='Drupal 10' /></head>",
        );
        assert_eq!(result, Some("Drupal 10".into()));
    }
}
