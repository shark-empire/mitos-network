use mitos_network::connectivity::captive_portal::classify;
use mitos_network::connectivity::ConnectivityState;

#[test]
fn expected_status_means_full_connectivity() {
    assert_eq!(classify(204, 204, false), ConnectivityState::Full);
}

#[test]
fn redirect_means_captive_portal() {
    assert_eq!(classify(302, 204, true), ConnectivityState::Portal);
    assert_eq!(classify(302, 204, false), ConnectivityState::Portal); // status alone is enough, even without a Location header
}

#[test]
fn unexpected_2xx_is_limited_not_full() {
    assert_eq!(classify(200, 204, false), ConnectivityState::Limited);
}

#[test]
fn server_error_is_limited() {
    assert_eq!(classify(503, 204, false), ConnectivityState::Limited);
}
