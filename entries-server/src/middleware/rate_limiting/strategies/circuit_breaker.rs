use std::net::IpAddr;

use super::super::RateLimiterStrategy;

/// Generates subnet-based keys (IPv4 /24 and IPv6 /64).
#[derive(Clone, Copy)]
pub struct CircuitBreaker;

impl RateLimiterStrategy for CircuitBreaker {
    #[inline]
    fn gen_key_and_shard_idx<const SHARDS: usize>(ip: IpAddr) -> (u128, u8) {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                // Last significant octet in /24 subnet is the third octet
                // Safe: IPv4 octets() always returns [u8; 4]
                let distinguishing_octet = unsafe { *octets.get_unchecked(2) };
                // Safe: IPv4 octets() always returns [u8; 4], so indices 0-2 are always valid
                let key = unsafe {
                    u32::from_be_bytes([
                        *octets.get_unchecked(0),
                        *octets.get_unchecked(1),
                        *octets.get_unchecked(2),
                        0,
                    ]) as u128
                };
                (key, distinguishing_octet)
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                // Last significant octet in /64 subnet is the eighth octet
                // Safe: IPv6 octets() always returns [u8; 16]
                let distinguishing_octet = unsafe { *octets.get_unchecked(7) };
                // Store the /64 subnet in the upper 64 bits, lower 64 bits are zero (big-endian).
                // Safe: IPv6 octets() always returns [u8; 16], so indices 0-7 are always valid
                let upper = unsafe {
                    u64::from_be_bytes([
                        *octets.get_unchecked(0),
                        *octets.get_unchecked(1),
                        *octets.get_unchecked(2),
                        *octets.get_unchecked(3),
                        *octets.get_unchecked(4),
                        *octets.get_unchecked(5),
                        *octets.get_unchecked(6),
                        *octets.get_unchecked(7),
                    ])
                };
                let key = (upper as u128) << 64;
                (key, distinguishing_octet)
            }
        }
    }

    fn format_key_for_log(ip: IpAddr, _key: u128) -> String {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        test_utils::{init_shared_test_logger, SHARED_WARNINGS},
        RateLimiter,
    };
    use super::CircuitBreaker;
    use actix_web::{http::StatusCode, test, web, App, HttpResponse};
    use std::time::Duration;
    use tokio::time::sleep;

    #[actix_web::test]
    async fn test_circuit_breaker_limiter_ipv4_subnet() {
        let limiter = RateLimiter::<CircuitBreaker, 16>::new(
            2,
            Duration::from_millis(5),
            Duration::from_millis(8),
            "circuit_breaker_ipv4",
        );

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Requests from different IPs in the same /24 subnet (127.0.0.0/24) should share the limit
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
            "First request from subnet should be allowed"
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
            "Second request from same subnet should be allowed"
        );

        // Third request from same subnet should be blocked (limit is 2)
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.99"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request from same subnet should be blocked"
        );

        // Request from different /24 subnet should be allowed
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

        // Period has expired, so we should be able to make requests from the original subnet again
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "127.0.0.3"))
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
            .append_header(("x-forwarded-for", "127.0.0.4"))
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
            .append_header(("x-forwarded-for", "127.0.0.5"))
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
    async fn test_circuit_breaker_limiter_ipv6_subnet() {
        let limiter = RateLimiter::<CircuitBreaker, 16>::new(
            2,
            Duration::from_millis(5),
            Duration::from_millis(8),
            "circuit_breaker_ipv6",
        );

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Requests from different IPs in the same /64 subnet (b24c:089b:7a21:1aff::/64) should share the limit
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
            "First request from subnet should be allowed"
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
            "Second request from same subnet should be allowed"
        );

        // Third request from same subnet should be blocked (limit is 2)
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::abcd"))
            .to_request();
        let status = match test::try_call_service(&app, req).await {
            Ok(res) => res.status(),
            Err(err) => err.as_response_error().status_code(),
        };
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "Third request from same subnet should be blocked"
        );

        // Request from different /64 subnet should be allowed
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

        // Period has expired, so we should be able to make requests from the original subnet again
        let req = test::TestRequest::default()
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::3"))
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
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::4"))
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
            .append_header(("x-forwarded-for", "b24c:089b:7a21:1aff::5"))
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
    async fn test_circuit_breaker_limiter_warning_logging() {
        init_shared_test_logger();
        // Clear warnings at the start of this test
        SHARED_WARNINGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        // Skip test if configuration is not available (e.g., missing env vars)
        let warn_every =
            match std::panic::catch_unwind(|| crate::env::CONF.api_limiter_warn_every_over_limit) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Skipping test: configuration not available (missing env vars)");
                    return;
                }
            };
        if warn_every == 0 {
            eprintln!("Skipping test: warn_every_over_limit is 0 (warnings disabled)");
            return;
        }

        let limit = 2u32;
        let limiter = RateLimiter::<CircuitBreaker, 16>::new(
            limit as u64,
            Duration::from_millis(100),
            Duration::from_millis(200),
            "circuit_breaker_test",
        );

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Warnings occur at: limit+1, limit+1+warn_every, limit+1+2*warn_every, limit+1+3*warn_every
        // To get 4 warnings, need count = limit + 1 + 3*warn_every
        let requests_needed = limit + 1 + (3 * warn_every);

        // Make requests from same subnet (they share the limit)
        for i in 1..=limit {
            let req = test::TestRequest::default()
                .append_header(("x-forwarded-for", format!("127.0.0.{}", i)))
                .to_request();
            let status = match test::try_call_service(&app, req).await {
                Ok(res) => res.status(),
                Err(err) => err.as_response_error().status_code(),
            };
            assert_eq!(status, StatusCode::OK, "Request {} should be allowed", i);
        }

        for i in (limit + 1)..=requests_needed {
            let req = test::TestRequest::default()
                .append_header(("x-forwarded-for", format!("127.0.0.{}", i)))
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
            .filter(|w| w.contains("limiter_name=circuit_breaker_test"))
            .collect();

        assert!(
            warnings_for_limiter.len() >= expected_warnings,
            "Expected at least {} warnings for limiter_name=circuit_breaker_test (warn_every={}, limit={}, requests={}), got {} total warnings / {} matching",
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
            assert!(
                warning.contains("/24") || warning.contains("/64"),
                "Warning should contain subnet mask, got: {}",
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
                warning.contains("limiter_name=circuit_breaker_test"),
                "Warning should contain limiter name, got: {}",
                warning
            );
        }
    }
}
