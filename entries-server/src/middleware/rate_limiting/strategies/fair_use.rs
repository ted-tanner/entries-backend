use std::net::IpAddr;

use super::super::RateLimiterStrategy;

/// Generates IP-based keys (full IP address).
#[derive(Clone, Copy)]
pub struct FairUse;

impl RateLimiterStrategy for FairUse {
    #[inline]
    fn gen_key_and_shard_idx<const SHARDS: usize>(ip: IpAddr) -> (u128, u8) {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                // Use the last octet for sharding
                let distinguishing_octet = octets[3];
                // Store IPv4 address in lower 32 bits, upper bits are zero
                let key = u32::from_be_bytes(octets) as u128;
                (key, distinguishing_octet)
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                // Use the last octet for sharding
                // Safe: IPv6 octets() always returns [u8; 16]
                let distinguishing_octet = unsafe { *octets.get_unchecked(15) };
                // Store full IPv6 address in a u128 (big-endian)
                // Safe: IPv6 octets() always returns [u8; 16], so indices 0-15 are always valid
                let key = unsafe {
                    u128::from_be_bytes([
                        *octets.get_unchecked(0),
                        *octets.get_unchecked(1),
                        *octets.get_unchecked(2),
                        *octets.get_unchecked(3),
                        *octets.get_unchecked(4),
                        *octets.get_unchecked(5),
                        *octets.get_unchecked(6),
                        *octets.get_unchecked(7),
                        *octets.get_unchecked(8),
                        *octets.get_unchecked(9),
                        *octets.get_unchecked(10),
                        *octets.get_unchecked(11),
                        *octets.get_unchecked(12),
                        *octets.get_unchecked(13),
                        *octets.get_unchecked(14),
                        *octets.get_unchecked(15),
                    ])
                };
                (key, distinguishing_octet)
            }
        }
    }

    fn format_key_for_log(ip: IpAddr, _key: u128) -> String {
        ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        test_utils::{init_shared_test_logger, SHARED_WARNINGS},
        RateLimiter,
    };
    use super::FairUse;
    use actix_web::{http::StatusCode, test, web, App, HttpResponse};
    use std::time::Duration;
    use tokio::time::sleep;

    #[actix_web::test]
    async fn test_fair_use_limiter_ipv4_individual_ips() {
        let limiter = RateLimiter::<FairUse, 16>::new(
            2,
            Duration::from_millis(5),
            Duration::from_millis(8),
            "fair_use_ipv4",
        );

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Different IPs in the same subnet should have separate limits
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "First request from IP 127.0.0.1 should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Second request from IP 127.0.0.1 should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request from IP 127.0.0.1 should be blocked"
        );

        // Different IP in the same subnet should have its own limit
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.2"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Request from different IP in same subnet should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.2"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Second request from IP 127.0.0.2 should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.2"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request from IP 127.0.0.2 should be blocked"
        );

        // IP from different subnet should also have its own limit
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.1.1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Request from different subnet should be allowed"
        );

        sleep(Duration::from_millis(5)).await;

        // Period has expired, so we should be able to make requests from the original IP again
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Request after period expiration should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Second request after period expiration should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request after period expiration should be blocked"
        );
    }

    #[actix_web::test]
    async fn test_fair_use_limiter_ipv6_individual_ips() {
        let limiter = RateLimiter::<FairUse, 16>::new(
            2,
            Duration::from_millis(5),
            Duration::from_millis(8),
            "fair_use_ipv6",
        );

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Different IPs in the same subnet should have separate limits
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "First request from IP should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Second request from same IP should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request from same IP should be blocked"
        );

        // Different IP in the same subnet should have its own limit
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::2"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Request from different IP in same subnet should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::2"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Second request from IP should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::2"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request from IP should be blocked"
        );

        // IP from different subnet should also have its own limit
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1bff::1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Request from different subnet should be allowed"
        );

        sleep(Duration::from_millis(5)).await;

        // Period has expired, so we should be able to make requests from the original IP again
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Request after period expiration should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "Second request after period expiration should be allowed"
        );

        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::1"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request after period expiration should be blocked"
        );
    }

    #[actix_web::test]
    async fn test_fair_use_limiter_warning_logging() {
        init_shared_test_logger();
        // Clear warnings at the start of this test
        SHARED_WARNINGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        let warn_every = crate::env::CONF.api_limiter_warn_every_over_limit;
        if warn_every == 0 {
            eprintln!("Skipping test: warn_every_over_limit is 0 (warnings disabled)");
            return;
        }

        let limit = 2u32;
        let limiter = RateLimiter::<FairUse, 16>::new(
            limit as u64,
            Duration::from_millis(100),
            Duration::from_millis(200),
            "fair_use_test",
        );

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Warnings occur at: limit+1, limit+1+warn_every, limit+1+2*warn_every, limit+1+3*warn_every
        // To get 4 warnings, need count = limit + 1 + 3*warn_every
        let requests_needed = limit + 1 + (3 * warn_every);

        // Make requests from same IP (they share the limit)
        for i in 1..=limit {
            let req = test::TestRequest::default()
                .append_header(("x-forwarded-for", "127.0.0.1"))
                .to_request();
            let status = match test::try_call_service(&app, req).await {
                Ok(res) => res.status(),
                Err(err) => err.as_response_error().status_code(),
            };
            assert_eq!(status, StatusCode::OK, "Request {} should be allowed", i);
        }

        for i in (limit + 1)..=requests_needed {
            let req = test::TestRequest::default()
                .append_header(("x-forwarded-for", "127.0.0.1"))
                .to_request();
            let status = match test::try_call_service(&app, req).await {
                Ok(res) => res.status(),
                Err(err) => err.as_response_error().status_code(),
            };
            assert_eq!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should be blocked",
                i
            );
        }

        let warnings = SHARED_WARNINGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let expected_warnings = 4;

        let warnings_for_limiter: Vec<&String> = warnings
            .iter()
            .filter(|w| w.contains("limiter_name=fair_use_test"))
            .collect();

        assert!(
            warnings_for_limiter.len() >= expected_warnings,
            "Expected at least {} warnings for limiter_name=fair_use_test (warn_every={}, limit={}, requests={}), got {} total warnings / {} matching",
            expected_warnings,
            warn_every,
            limit,
            requests_needed,
            warnings.len(),
            warnings_for_limiter.len()
        );

        for warning in warnings_for_limiter.iter() {
            assert!(
                warning.contains("Rate-limited request"),
                "Warning should contain 'Rate-limited request', got: {}",
                warning
            );
            assert!(
                warning.contains("key="),
                "Warning should contain 'key=', got: {}",
                warning
            );
            // For IP-based limiting, the key should be the IP address (not a subnet)
            assert!(
                warning.contains("127.0.0.1") || warning.contains("key="),
                "Warning should contain IP address or 'key=', got: {}",
                warning
            );
            assert!(
                warning.contains(&format!("warn_every={}", warn_every)),
                "Warning should contain 'warn_every={}', got: {}",
                warn_every,
                warning
            );
            assert!(
                warning.contains(&format!("limit={}", limit)),
                "Warning should contain 'limit={}', got: {}",
                limit,
                warning
            );
            assert!(
                warning.contains("limiter_name=fair_use_test"),
                "Warning should contain limiter name, got: {}",
                warning
            );
        }
    }
}
