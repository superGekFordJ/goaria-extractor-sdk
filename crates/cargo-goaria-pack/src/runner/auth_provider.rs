use std::collections::HashMap;

use goaria_extractor_sdk::types::{
    AuthSecretKind, HostAuthProfileStatusRequest, HostAuthProfileStatusResponse,
};

use crate::manifest::Manifest;
use crate::runner::limits::HostCallBudget;

/// Configuration for a simulated auth profile.
#[derive(Debug, Clone)]
pub struct AuthProfileEntry {
    pub id: String,
    pub available: bool,
    pub kind: AuthSecretKind,
    pub redacted_display: String,
    pub raw_secret: Option<String>,
}

/// Simulates authentication status and secret injection for the host runner.
#[derive(Debug, Default, Clone)]
pub struct AuthProvider {
    profiles: HashMap<String, AuthProfileEntry>,
}

impl AuthProvider {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    pub fn add_profile(
        &mut self,
        id: impl Into<String>,
        available: bool,
        kind: AuthSecretKind,
        redacted_display: impl Into<String>,
        raw_secret: Option<String>,
    ) -> &mut Self {
        let id_str = id.into();
        self.profiles.insert(
            id_str.clone(),
            AuthProfileEntry {
                id: id_str,
                available,
                kind,
                redacted_display: redacted_display.into(),
                raw_secret,
            },
        );
        self
    }

    pub fn get_secret(&self, id: &str) -> Option<String> {
        self.profiles.get(id).and_then(|p| p.raw_secret.clone())
    }

    pub fn handle_status(
        &self,
        manifest: &Manifest,
        budget: &mut HostCallBudget,
        req: HostAuthProfileStatusRequest,
    ) -> HostAuthProfileStatusResponse {
        // 1. Consume budget
        if let Err(e) = budget.consume() {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("budget_exhausted".to_string()),
                message: Some(e.to_string()),
                ..Default::default()
            };
        }

        // 2. Validate capability
        if !manifest.has_capability("cap.auth.profile") {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("permission_denied".to_string()),
                message: Some("pack does not have capability 'cap.auth.profile'".to_string()),
                ..Default::default()
            };
        }

        // 3. Validate domain if URL is present
        if let Some(url) = &req.url {
            match manifest.allows_url(url) {
                Ok(true) => {}
                Ok(false) => {
                    return HostAuthProfileStatusResponse {
                        ok: false,
                        error_code: Some("domain_not_allowed".to_string()),
                        message: Some(format!(
                            "URL '{}' not allowed by manifest domain rules",
                            url
                        )),
                        ..Default::default()
                    };
                }
                Err(e) => {
                    return HostAuthProfileStatusResponse {
                        ok: false,
                        error_code: Some("invalid_url".to_string()),
                        message: Some(e.to_string()),
                        ..Default::default()
                    };
                }
            }
        }

        // 4. Query profile registry
        match self.profiles.get(&req.auth_profile_ref) {
            Some(profile) => HostAuthProfileStatusResponse {
                ok: true,
                available: Some(profile.available),
                kind: Some(profile.kind),
                redacted_display: Some(profile.redacted_display.clone()),
                error_code: None,
                message: None,
            },
            None => HostAuthProfileStatusResponse {
                ok: true,
                available: Some(false),
                kind: None,
                redacted_display: None,
                error_code: None,
                message: Some(format!("auth profile '{}' not found", req.auth_profile_ref)),
            },
        }
    }
}
