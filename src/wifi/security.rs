use serde::{Deserialize, Serialize};

/// The security types mitos-network can join or configure. Ordered
/// roughly by era/strength; `Ord` isn't derived since "stronger" isn't
/// always well-defined across enterprise vs. personal variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityType {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa3Sae,
    WpaEnterprise,
    Wpa3Enterprise,
}

impl SecurityType {
    /// The wpa_supplicant `key_mgmt` value for `SET_NETWORK <id> key_mgmt ...`.
    pub fn key_mgmt(self) -> &'static str {
        match self {
            SecurityType::Open | SecurityType::Wep => "NONE",
            SecurityType::WpaPsk | SecurityType::Wpa2Psk => "WPA-PSK",
            SecurityType::Wpa3Sae => "SAE",
            SecurityType::WpaEnterprise => "WPA-EAP",
            SecurityType::Wpa3Enterprise => "WPA-EAP-SUITE-B-192",
        }
    }

    pub fn needs_passphrase(self) -> bool {
        !matches!(self, SecurityType::Open)
    }

    pub fn is_enterprise(self) -> bool {
        matches!(
            self,
            SecurityType::WpaEnterprise | SecurityType::Wpa3Enterprise
        )
    }

    /// Classifies a scan result's capability flags string, e.g.
    /// `"[WPA2-PSK-CCMP][ESS]"` or `"[WPA2-EAP-CCMP][WPA3-SAE-CCMP][ESS]"`
    /// (a transition-mode AP) -- picks the strongest option offered.
    pub fn from_flags(flags: &str) -> SecurityType {
        let has = |needle: &str| flags.contains(needle);
        if has("SAE") {
            if has("EAP") {
                SecurityType::Wpa3Enterprise
            } else {
                SecurityType::Wpa3Sae
            }
        } else if has("EAP") {
            SecurityType::WpaEnterprise
        } else if has("WPA2") || has("RSN") {
            SecurityType::Wpa2Psk
        } else if has("WPA") {
            SecurityType::WpaPsk
        } else if has("WEP") {
            SecurityType::Wep
        } else {
            SecurityType::Open
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_flag_strings() {
        assert_eq!(SecurityType::from_flags("[ESS]"), SecurityType::Open);
        assert_eq!(
            SecurityType::from_flags("[WPA2-PSK-CCMP][ESS]"),
            SecurityType::Wpa2Psk
        );
        assert_eq!(
            SecurityType::from_flags("[SAE-CCMP][ESS]"),
            SecurityType::Wpa3Sae
        );
        assert_eq!(
            SecurityType::from_flags("[WPA2-EAP-CCMP][ESS]"),
            SecurityType::WpaEnterprise
        );
    }
}
