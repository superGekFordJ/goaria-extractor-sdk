use std::collections::HashMap;

use goaria_extractor_sdk::types::{
    AuthSecretKind, HostAuthProfileStatusRequest, HostAuthProfileStatusResponse,
};

use crate::manifest::Manifest;
use crate::runner::host_broker::{
    check_hop_target, is_alias_manifest, is_valid_profile_slug, validate_ref_params,
};
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

        // 2. Profile ref must be a well-formed slug before any policy work.
        if !is_valid_profile_slug(&req.auth_profile_ref) {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some(
                    "auth_profile_ref must be a lowercase slug of 1-64 characters".to_string(),
                ),
                ..Default::default()
            };
        }

        // 3. Mode determination: url never mixes with ref fields, refs come
        //    as a pair, and params are validated like the fetch import.
        let has_url = req.url.as_deref().is_some_and(|u| !u.is_empty());
        let has_broker_ref = req
            .broker_policy_ref
            .as_deref()
            .is_some_and(|r| !r.is_empty());
        let has_endpoint_ref = req.endpoint_ref.as_deref().is_some_and(|r| !r.is_empty());
        if has_url && (has_broker_ref || has_endpoint_ref) {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some("raw url must not be combined with ref-mode fields".to_string()),
                ..Default::default()
            };
        }
        if has_broker_ref != has_endpoint_ref {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some(
                    "broker_policy_ref and endpoint_ref must be provided together".to_string(),
                ),
                ..Default::default()
            };
        }
        // Alias manifests only speak refs; plain manifests only raw urls.
        if has_url && is_alias_manifest(manifest) {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some(
                    "alias manifests require broker_policy_ref and endpoint_ref".to_string(),
                ),
                ..Default::default()
            };
        }
        if has_broker_ref && !is_alias_manifest(manifest) {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some("ref-mode fields require an alias manifest".to_string()),
                ..Default::default()
            };
        }
        if let Some(params) = req.params.as_ref().filter(|p| !p.is_empty()) {
            if let Err(deny) = validate_ref_params(params) {
                return HostAuthProfileStatusResponse {
                    ok: false,
                    error_code: Some(deny.error_code.to_string()),
                    message: Some(deny.message),
                    ..Default::default()
                };
            }
        }
        if !has_url && !has_broker_ref {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some(
                    "request must provide either url or broker_policy_ref with endpoint_ref"
                        .to_string(),
                ),
                ..Default::default()
            };
        }

        // 4. Capability + policy gates classify as policy_denied.
        if !manifest.has_capability("cap.auth.profile") {
            return HostAuthProfileStatusResponse {
                ok: false,
                error_code: Some("policy_denied".to_string()),
                message: Some("pack does not have capability 'cap.auth.profile'".to_string()),
                ..Default::default()
            };
        }
        if has_broker_ref {
            let declared = manifest.broker_policy_refs.as_deref().unwrap_or(&[]);
            if !declared
                .iter()
                .any(|r| r == req.broker_policy_ref.as_deref().unwrap_or_default())
            {
                return HostAuthProfileStatusResponse {
                    ok: false,
                    error_code: Some("policy_denied".to_string()),
                    message: Some("host policy endpoint is not available".to_string()),
                    ..Default::default()
                };
            }
        }
        if has_url {
            // Reuse the shared egress gate so dangerous schemes and unsafe
            // hosts are denied exactly like a fetch hop.
            let url = req.url.as_deref().unwrap_or_default();
            if check_hop_target(url, manifest, false, false).is_err() {
                return HostAuthProfileStatusResponse {
                    ok: false,
                    error_code: Some("policy_denied".to_string()),
                    message: Some("request url is not allowed by manifest policy".to_string()),
                    ..Default::default()
                };
            }
        }

        // 5. Query profile registry; a miss is an unavailable profile, not a
        //    successful "not found" status.
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
                ok: false,
                available: None,
                kind: None,
                redacted_display: None,
                error_code: Some("auth_unavailable".to_string()),
                message: Some("auth profile unavailable".to_string()),
            },
        }
    }
}
