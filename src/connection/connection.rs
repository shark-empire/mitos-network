//! Runtime state for a profile that is (or was recently) active --
//! distinct from `ConnectionProfile`, which is the persisted "recipe".

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActiveConnectionState {
    Activating,
    Activated,
    Deactivating,
    Deactivated,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveConnection {
    pub profile_id: String,
    pub device_name: String,
    pub state: ActiveConnectionState,
    #[serde(skip, default = "SystemTime::now")]
    pub since: SystemTime,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

impl ActiveConnection {
    pub fn activating(profile_id: impl Into<String>, device_name: impl Into<String>) -> Self {
        ActiveConnection {
            profile_id: profile_id.into(),
            device_name: device_name.into(),
            state: ActiveConnectionState::Activating,
            since: SystemTime::now(),
            failure_reason: None,
        }
    }
}
