use std::{sync::Arc, time::Duration};
use regex::Regex;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecureRoute {
    pub path_pattern: String,
    pub methods: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionExtraction {
    pub cookie_name: Option<String>,
    pub header_name: Option<String>,
    pub header_bearer: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EGuardConfig {
    pub api_base_url: String,
    pub api_key: String,
    pub secure_routes: Vec<SecureRoute>,
    pub session_extraction: SessionExtraction,
    pub min_trust_score: f32,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 { 1500 }

#[derive(Clone)]
struct CompiledRoute {
    re: Regex,
    methods: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct EGuard {
    cfg: Arc<EGuardConfig>,
    client: Client,
    routes: Vec<CompiledRoute>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustResponse {
    pub session_id: String,
    pub trust_score: f32,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny { status: u16, message: String },
}

impl EGuard {
    pub fn new(cfg: EGuardConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()?;

        let routes = cfg.secure_routes.iter()
            .map(|r| {
                let re = Regex::new(&r.path_pattern)
                    .map_err(|e| anyhow::anyhow!("Invalid route regex {}: {}", r.path_pattern, e))?;
                let methods = r.methods.as_ref().map(|v| v.iter().map(|m| m.to_uppercase()).collect());
                Ok(CompiledRoute { re, methods })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self { cfg: Arc::new(cfg), client, routes })
    }

    pub fn is_secure(&self, path: &str, method: &str) -> bool {
        let m = method.to_uppercase();
        self.routes.iter().any(|r| {
            if !r.re.is_match(path) { return false; }
            match &r.methods {
                None => true,
                Some(ms) => ms.iter().any(|mm| mm == &m),
            }
        })
    }

    pub fn extract_session_id(
        &self,
        cookies: Option<&str>,
        header_name_val: Option<(&str, &str)>,
    ) -> Option<String> {

        if let Some(cookie_name) = &self.cfg.session_extraction.cookie_name {
            if let Some(raw) = cookies {
                for pair in raw.split(';') {
                    let mut it = pair.trim().splitn(2, '=');
                    if let (Some(k), Some(v)) = (it.next(), it.next()) {
                        if k == cookie_name {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
        
        if let Some(hn) = &self.cfg.session_extraction.header_name {
            if let Some((name, val)) = header_name_val {
                if hn.eq_ignore_ascii_case(name) {
                    if self.cfg.session_extraction.header_bearer {
                        let v = val.trim();
                        if let Some(rest) = v.strip_prefix("Bearer ") {
                            return Some(rest.to_string());
                        }
                    }
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    pub async fn fetch_trust(&self, session_id: &str) -> anyhow::Result<TrustResponse> {
        let url = format!("{}/eguard/trust", self.cfg.api_base_url);
        let resp = self.client
            .get(url)
            .query(&[("sid", session_id)])
            .bearer_auth(&self.cfg.api_key)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json::<TrustResponse>().await?)
        } else if resp.status() == StatusCode::NOT_FOUND {
            Ok(TrustResponse { session_id: session_id.into(), trust_score: 0.0, reason: Some("unknown_session".into()) })
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("Trust API error {}: {}", status, body))
        }
    }

    pub async fn decide(&self, session_id: &str) -> anyhow::Result<Decision> {
        let trust = self.fetch_trust(session_id).await?;
        if trust.trust_score >= self.cfg.min_trust_score {
            Ok(Decision::Allow)
        } else {
            Ok(Decision::Deny {
                status: 403,
                message: format!("Low trust score: {}", trust.trust_score),
            })
        }
    }
}