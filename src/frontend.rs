use crate::technology::Frontend;

use crate::util;

pub struct FrontendDetection {
    pub frontend: Frontend,
    pub version: Option<String>,
    pub confidence: f64,
}

pub fn detect_frontend(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<FrontendDetection> {
    if let Some(result) = detect_from_body(body) {
        return Some(result);
    }
    detect_from_headers(headers)
}

#[allow(clippy::too_many_lines)]
fn detect_from_body(body: Option<&str>) -> Option<FrontendDetection> {
    let text = util::body_str(body);
    if text.is_empty() {
        return None;
    }

    if text.contains("data-reactroot")
        || text.contains("_reactRootContainer")
        || text.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__")
        || (text.contains("react.") && text.contains(".js"))
    {
        return Some(FrontendDetection {
            frontend: Frontend::React,
            version: extract_react_version(text),
            confidence: 0.9,
        });
    }

    if text.contains("ng-app")
        || text.contains("ng-controller")
        || text.contains("ng-model")
        || text.contains("ng-version")
        || text.contains("angular.min.js")
        || text.contains("angular.js")
    {
        return Some(FrontendDetection {
            frontend: Frontend::Angular,
            version: extract_angular_version(text),
            confidence: 0.9,
        });
    }

    if text.contains("data-v-")
        || text.contains("__vue__")
        || text.contains("vue.min.js")
        || text.contains("vue.global")
        || text.contains("v-cloak")
    {
        return Some(FrontendDetection {
            frontend: Frontend::Vue,
            version: extract_vue_version(text),
            confidence: 0.9,
        });
    }

    if text.contains("__svelte") || text.contains("svelte-") {
        return Some(FrontendDetection {
            frontend: Frontend::Svelte,
            version: None,
            confidence: 0.8,
        });
    }

    if text.contains("ember-application")
        || text.contains("ember.min.js")
        || text.contains("ember-view")
    {
        return Some(FrontendDetection {
            frontend: Frontend::Ember,
            version: None,
            confidence: 0.9,
        });
    }

    if text.contains("jquery.min.js")
        || text.contains("jquery.js")
        || text.contains("jquery-")
    {
        return Some(FrontendDetection {
            frontend: Frontend::jQuery,
            version: extract_jquery_version(text),
            confidence: 0.8,
        });
    }

    None
}

fn detect_from_headers(headers: &[(String, String)]) -> Option<FrontendDetection> {
    if util::header_contains(headers, "x-powered-by", "next.js") {
        return Some(FrontendDetection {
            frontend: Frontend::React,
            version: None,
            confidence: 0.8,
        });
    }
    None
}

fn extract_react_version(body: &str) -> Option<String> {
    util::extract_version(body, "react@")
        .or_else(|| util::extract_version(body, "react/"))
}

fn extract_angular_version(body: &str) -> Option<String> {
    if let Some(idx) = body.find("ng-version=\"") {
        let after = &body[idx + 12..];
        let version: String = after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !version.is_empty() {
            return Some(version);
        }
    }
    util::extract_version(body, "angular@")
}

fn extract_vue_version(body: &str) -> Option<String> {
    util::extract_version(body, "vue@").or_else(|| util::extract_version(body, "vue/"))
}

fn extract_jquery_version(body: &str) -> Option<String> {
    util::extract_version(body, "jquery-")
        .or_else(|| util::extract_version(body, "jquery/"))
        .or_else(|| util::extract_version(body, "jquery@"))
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn detect_react() {
        let b = Some(r#"<div id="root" data-reactroot=""></div>"#);
        let result = detect_frontend(&[], b).unwrap();
        assert!(matches!(result.frontend, Frontend::React));
    }

    #[test]
    fn detect_react_with_version() {
        let b = Some(r#"<script src="https://cdn.example.com/react@18.2.0/umd/react.production.min.js"></script>"#);
        let result = detect_frontend(&[], b).unwrap();
        assert!(matches!(result.frontend, Frontend::React));
        assert_eq!(result.version, Some("18.2.0".into()));
    }

    #[test]
    fn detect_angular() {
        let b = Some(r#"<html ng-app="myApp" ng-version="17.1.0"><body ng-controller="MainCtrl"></body></html>"#);
        let result = detect_frontend(&[], b).unwrap();
        assert!(matches!(result.frontend, Frontend::Angular));
        assert_eq!(result.version, Some("17.1.0".into()));
    }

    #[test]
    fn detect_vue() {
        let b = Some(r#"<div data-v-abc123 class="app"><div v-cloak></div></div>"#);
        let result = detect_frontend(&[], b).unwrap();
        assert!(matches!(result.frontend, Frontend::Vue));
    }

    #[test]
    fn detect_svelte() {
        let b = Some(r#"<div class="svelte-1abc2de">content</div><script src="/__svelte/bundle.js"></script>"#);
        let result = detect_frontend(&[], b).unwrap();
        assert!(matches!(result.frontend, Frontend::Svelte));
    }

    #[test]
    fn detect_ember() {
        let b = Some(r#"<div id="ember-application"><script src="/assets/ember.min.js"></script></div>"#);
        let result = detect_frontend(&[], b).unwrap();
        assert!(matches!(result.frontend, Frontend::Ember));
    }

    #[test]
    fn detect_jquery() {
        let b = Some(r#"<script src="/js/jquery-3.7.1.min.js"></script>"#);
        let result = detect_frontend(&[], b).unwrap();
        assert!(matches!(result.frontend, Frontend::jQuery));
        assert_eq!(result.version, Some("3.7.1".into()));
    }

    #[test]
    fn detect_react_from_nextjs_header() {
        let headers = vec![("X-Powered-By".into(), "Next.js".into())];
        let result = detect_frontend(&headers, None).unwrap();
        assert!(matches!(result.frontend, Frontend::React));
    }

    #[test]
    fn no_frontend_detected() {
        let b = Some("<html><body><p>Simple page</p></body></html>");
        assert!(detect_frontend(&[], b).is_none());
    }
}
