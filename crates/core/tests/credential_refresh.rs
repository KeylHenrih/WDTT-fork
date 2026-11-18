//! Tests for the TURN credential refresh plumbing.
//!
//! The refresh path itself needs a live relay to exercise end to end, so these
//! tests pin the two pieces the runtime depends on: which errors count as an
//! authentication failure, and that the refresher hook is wired through the
//! client configuration and can be invoked.

use std::net::SocketAddr;
use wdtt_core::tunnel::{CredentialRefresher, CredentialFuture, RefreshedCredentials};
use wdtt_core::TunnelError;
use wdtt_turn::TurnError;

#[test]
fn stun_auth_error_codes_are_auth_failures() {
    for code in [401u16, 403, 438] {
        let err = TunnelError::Turn(TurnError::StunErrorResponse {
            code,
            reason: "unauthorized".into(),
        });
        assert!(
            err.is_auth_failure(),
            "STUN code {code} should count as an auth failure"
        );
    }
}

#[test]
fn allocation_failure_is_an_auth_failure() {
    let err = TunnelError::Turn(TurnError::AllocationFailed);
    assert!(err.is_auth_failure());
}

#[test]
fn unauthorized_error_is_an_auth_failure() {
    let err = TunnelError::Unauthorized("credentials lapsed".into());
    assert!(err.is_auth_failure());
}

#[test]
fn transport_and_timeout_errors_are_not_auth_failures() {
    assert!(!TunnelError::Turn(TurnError::Transport("closed".into())).is_auth_failure());
    assert!(!TunnelError::Turn(TurnError::Timeout).is_auth_failure());
    assert!(!TunnelError::Timeout("no response".into()).is_auth_failure());
    assert!(
        !TunnelError::Turn(TurnError::StunErrorResponse {
            code: 500,
            reason: "server error".into(),
        })
        .is_auth_failure()
    );
}

#[tokio::test]
async fn refresher_runs_the_wrapped_callback() {
    let addr: SocketAddr = "203.0.113.7:443".parse().unwrap();
    let refresher = CredentialRefresher::new(std::sync::Arc::new(move || {
        Box::pin(async move {
            Ok(RefreshedCredentials {
                username: "user".into(),
                password: "secret".into(),
                realm: "realm".into(),
                server_addr: addr,
                sni: Some("example.test".into()),
                expires_at: 42,
            })
        }) as CredentialFuture
    }));

    let creds = refresher.run().await.expect("refresh should succeed");
    assert_eq!(creds.username, "user");
    assert_eq!(creds.password, "secret");
    assert_eq!(creds.server_addr, addr);
    assert_eq!(creds.sni.as_deref(), Some("example.test"));
    assert_eq!(creds.expires_at, 42);
}

#[tokio::test]
async fn refresher_propagates_callback_errors() {
    let refresher = CredentialRefresher::new(std::sync::Arc::new(|| {
        Box::pin(async move { Err("provider rate limited".to_string()) }) as CredentialFuture
    }));

    let err = refresher.run().await.expect_err("refresh should fail");
    assert!(err.contains("rate limited"));
}
