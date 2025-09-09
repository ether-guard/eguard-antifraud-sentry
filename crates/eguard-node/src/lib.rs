use eguard_core::{Decision, EGuard, EGuardConfig, SecureRoute, SessionExtraction};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;

static RT: OnceCell<Runtime> = OnceCell::new();

#[napi(object)]
pub struct JsSecureRoute {
  pub path_pattern: String,
  pub methods: Option<Vec<String>>,
}

#[napi(object)]
pub struct JsSessionExtraction {
  pub cookie_name: Option<String>,
  pub header_name: Option<String>,
  pub header_bearer: Option<bool>,
}

#[napi(object)]
pub struct JsEGuardConfig {
  pub api_base_url: String,
  pub api_key: String,
  pub secure_routes: Vec<JsSecureRoute>,
  pub session_extraction: JsSessionExtraction,
  pub min_trust_score: f64,
  pub timeout_ms: Option<u32>,
}

#[napi(object)]
pub struct JsDecision {
  pub allow: bool,
  pub status: Option<u16>,
  pub message: Option<String>,
}

#[napi]
pub struct JsEGuard {
  inner: EGuard,
}

#[napi]
impl JsEGuard {
  #[napi(constructor)]
  pub fn new(cfg: JsEGuardConfig) -> Result<Self> {
    
    RT.get_or_init(|| Runtime::new().expect("failed to create tokio runtime"));

    let core_cfg = EGuardConfig {
      api_base_url: cfg.api_base_url,
      api_key: cfg.api_key,
      secure_routes: cfg
        .secure_routes
        .into_iter()
        .map(|r| SecureRoute {
          path_pattern: r.path_pattern,
          methods: r.methods,
        })
        .collect(),
      session_extraction: SessionExtraction {
        cookie_name: cfg.session_extraction.cookie_name,
        header_name: cfg.session_extraction.header_name,
        header_bearer: cfg.session_extraction.header_bearer.unwrap_or(false),
      },
      
      min_trust_score: cfg.min_trust_score as f32,
      timeout_ms: cfg.timeout_ms.unwrap_or(1500) as u64,
    };

    let inner = EGuard::new(core_cfg).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(Self { inner })
  }

  #[napi]
  pub fn is_secure(&self, path: String, method: String) -> bool {
    self.inner.is_secure(&path, &method)
  }

  #[napi]
  pub fn extract_session_id(
    &self,
    cookie_header: Option<String>,
    header_name: Option<String>,
    header_value: Option<String>,
  ) -> Option<String> {
    match (header_name, header_value) {
      (Some(n), Some(v)) => self
        .inner
        .extract_session_id(cookie_header.as_deref(), Some((n.as_str(), v.as_str()))),
      _ => self.inner.extract_session_id(cookie_header.as_deref(), None),
    }
  }

  #[napi]
  pub fn decide(&self, session_id: String) -> AsyncTask<DecideTask> {
    AsyncTask::new(DecideTask {
      guard: self.inner.clone(),
      session_id,
    })
  }
}

pub struct DecideTask {
  guard: EGuard,
  session_id: String,
}

impl DecideTask {
  async fn run(&self) -> napi::Result<Decision> {
    self
      .guard
      .decide(&self.session_id)
      .await
      .map_err(|e| Error::from_reason(e.to_string()))
  }
}

#[napi]
impl Task for DecideTask {
  type Output = Decision;
  type JsValue = JsDecision;

  fn compute(&mut self) -> Result<Self::Output> {
    let rt = RT.get().expect("tokio runtime not initialized");
    rt.block_on(self.run())
  }

  fn resolve(&mut self, _env: Env, out: Decision) -> Result<Self::JsValue> {
    Ok(match out {
      Decision::Allow => JsDecision {
        allow: true,
        status: None,
        message: None,
      },
      Decision::Deny { status, message } => JsDecision {
        allow: false,
        status: Some(status),
        message: Some(message),
      },
    })
  }
}
