use mitos_network::security::validation::{
    validate_identifier, validate_interface_name, validate_ssid, validate_wpa_passphrase,
};

#[test]
fn interface_names_enforce_ifnamsiz() {
    assert!(validate_interface_name("eth0").is_ok());
    assert!(validate_interface_name("wlan0").is_ok());
    assert!(validate_interface_name("this-name-is-way-too-long-for-linux").is_err());
    assert!(validate_interface_name("").is_err());
    assert!(validate_interface_name("has space").is_err());
    assert!(validate_interface_name("has/slash").is_err());
}

#[test]
fn ssid_length_and_content_bounds() {
    assert!(validate_ssid("HomeNetwork").is_ok());
    assert!(validate_ssid("").is_err());
    assert!(validate_ssid(&"x".repeat(33)).is_err());
    assert!(validate_ssid("bad\"quote").is_err());
}

#[test]
fn wpa_passphrase_length_bounds() {
    assert!(validate_wpa_passphrase("short").is_err()); // < 8 chars
    assert!(validate_wpa_passphrase("just right").is_ok());
    assert!(validate_wpa_passphrase(&"x".repeat(64)).is_err()); // > 63 chars
    assert!(validate_wpa_passphrase("caf\u{e9}1234").is_err()); // non-ASCII
}

#[test]
fn identifiers_reject_injection_attempts() {
    assert!(validate_identifier("home-wifi_1.profile").is_ok());
    assert!(validate_identifier("../etc/passwd").is_err());
    assert!(validate_identifier("has space").is_err());
    assert!(validate_identifier("").is_err());
}
