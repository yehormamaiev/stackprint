use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fingerprint {
    pub server: Option<WebServer>,
    pub backend: Option<Backend>,
    pub frontend: Option<Frontend>,
    pub cms: Option<Cms>,
    pub waf: Option<Waf>,
    pub database: Option<Database>,
    pub cdn: Option<Cdn>,
    pub auth_type: Option<AuthType>,
    pub http_version: Option<crate::http::HttpVersion>,
    pub has_graphql: bool,
    pub has_grpc: bool,
    pub has_websocket: bool,
    pub has_openapi_spec: bool,
    pub has_mfa: bool,
    pub supports_h3: bool,
    pub raw_headers: Vec<(String, String)>,
    pub detected_technologies: Vec<DetectedTechnology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTechnology {
    pub name: String,
    pub version: Option<String>,
    pub category: TechCategory,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum TechCategory {
    Server,
    Framework,
    Cms,
    Waf,
    Cdn,
    Database,
    Language,
    JsFramework,
    Analytics,
    CacheProxy,
    LoadBalancer,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum WebServer {
    Apache,
    Nginx,
    Iis,
    LiteSpeed,
    Caddy,
    Envoy,
    Traefik,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum Backend {
    Django,
    Flask,
    FastApi,
    Rails,
    Spring,
    SpringBoot,
    Laravel,
    Symfony,
    Express,
    NextJs,
    NuxtJs,
    AspNet,
    AspNetCore,
    Phoenix,
    Gin,
    Fiber,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum Frontend {
    React,
    Angular,
    Vue,
    Svelte,
    Ember,
    #[allow(non_camel_case_types)]
    jQuery,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum Cms {
    WordPress,
    Drupal,
    Joomla,
    Ghost,
    Magento,
    Shopify,
    Strapi,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum Waf {
    Cloudflare,
    AwsWaf,
    Akamai,
    Imperva,
    ModSecurity,
    Sucuri,
    F5BigIp,
    Barracuda,
    Fortinet,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum Database {
    MySQL,
    PostgreSQL,
    SQLite,
    MsSql,
    Oracle,
    MongoDB,
    Redis,
    Cassandra,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum Cdn {
    Cloudflare,
    Fastly,
    Akamai,
    AwsCloudFront,
    AzureCdn,
    GoogleCloud,
    KeyCdn,
    StackPath,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum AuthType {
    Session,
    JWT,
    OAuth,
    SAML,
    BasicAuth,
    ApiKey,
    BearerToken,
    Certificate,
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_defaults() {
        let fp = Fingerprint::default();
        assert!(fp.server.is_none());
        assert!(!fp.has_graphql);
        assert!(!fp.supports_h3);
    }

    #[test]
    fn auth_type_display() {
        assert_eq!(AuthType::JWT.to_string(), "JWT");
        assert_eq!(AuthType::OAuth.to_string(), "OAuth");
    }
}
