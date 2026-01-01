use std::{
    future::{ready, Ready},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use crate::utils::limiter_table as rate_limit_table;
use crate::utils::limiter_table::LimiterTable;

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorTooManyRequests,
};
use futures::future::LocalBoxFuture;
use tokio::sync::RwLock;

// LimiterTable uses a single u64 as the key for both IPv4 /24 and IPv6 /64 subnets.
//
// - For IPv4, the /24 subnet is stored in the lower 32 bits of the u64 (upper 32 bits are zero).
// - For IPv6, the /64 subnet is stored as the upper 64 bits of the address (first 8 bytes).
//
// For every IPv4 /24 subnet, there is a collision with the IPv6 /64 subnet where the upper 96
// bits are zero and the lower 32 bits match the IPv4 subnet (e.g., 1.2.3.0/24 collides
// with ::1.2.3.0/64). Collisions are extremely unlikely to matter in practice (about 1 in 4.3
// billion chance for a random IPv6 subnet, probably even lower as real-world IPv6 subnets are
// not random). In the unlikely event that there is a collision, the only effect is that hits to
// either subnet will be counted for both.
#[derive(Clone)]
pub struct Limiter {
    max_per_period: u64,
    period: Duration,
    clear_frequency: Duration,
    limiter_tables: &'static [RwLock<LimiterTable<u64>>; 16],
}

impl Limiter {
    /// Should be created on a single thread. Panics if period is greater than clear frequency.
    pub fn new(max_per_period: u64, period: Duration, clear_frequency: Duration) -> Self {
        if period > clear_frequency {
            panic!("Period cannot be greater than clear frequency");
        }
        // 14 days in milliseconds
        let max_period_ms = 14 * 24 * 60 * 60 * 1000u64;
        if period.as_millis() as u64 >= max_period_ms {
            panic!("Limiter period must be less than 14 days (due to u32 ms wraparound)");
        }

        rate_limit_table::init_start();
        let limiter_tables = rate_limit_table::new_sharded_tables_16::<u64>();

        Limiter {
            max_per_period,
            period,
            clear_frequency,
            limiter_tables,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Limiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = LimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(LimiterMiddleware {
            service,

            max_per_period: self.max_per_period,
            period: self.period,
            clear_frequency: self.clear_frequency,

            limiter_tables: self.limiter_tables,
        }))
    }
}

pub struct LimiterMiddleware<S> {
    service: S,

    max_per_period: u64,
    period: Duration,
    clear_frequency: Duration,

    limiter_tables: &'static [RwLock<LimiterTable<u64>>; 16],
}

impl<S, B> Service<ServiceRequest> for LimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = {
            // peer_addr() only returns None in a test
            #[cfg(test)]
            {
                use actix_web::http::header::HeaderValue;
                use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
                use std::str::FromStr;

                let default_ip = HeaderValue::from_static("127.0.0.1");
                let test_ip = req
                    .headers()
                    .get("test-ip")
                    .unwrap_or(&default_ip)
                    .to_str()
                    .unwrap();

                if test_ip.len() < 16 {
                    let test_ip = Ipv4Addr::from_str(test_ip).expect("Invalid test IP");
                    SocketAddr::V4(SocketAddrV4::new(test_ip, 80))
                } else {
                    let test_ip = Ipv6Addr::from_str(test_ip).expect("Invalid test IP");
                    SocketAddr::V6(SocketAddrV6::new(test_ip, 80, 0, 0))
                }
            }
            #[cfg(not(test))]
            {
                req.peer_addr().expect("Address should always be available")
            }
        };

        let (ip, distinguishing_octet) = match ip {
            SocketAddr::V4(ip) => {
                let ip = ip.ip();
                // Last significant octet in /24 subnet is the third octet
                let distinguishing_octet = unsafe { *ip.octets().get_unchecked(2) };
                (IpAddr::V4(*ip), distinguishing_octet)
            }
            SocketAddr::V6(ip) => {
                let ip = ip.ip();
                // Last significant octet in /64 subnet is the eighth octet
                let distinguishing_octet = unsafe { *ip.octets().get_unchecked(7) };
                (IpAddr::V6(*ip), distinguishing_octet)
            }
        };

        let table_index = (distinguishing_octet & 0x0F) as usize;
        let shard = unsafe { self.limiter_tables.get_unchecked(table_index) };

        let req_fut = self.service.call(req);

        let max_per_period = self.max_per_period;
        let period = self.period;
        let clear_frequency = self.clear_frequency;

        Box::pin(async move {
            let now = Instant::now();
            let now_millis = rate_limit_table::now_millis_u32();

            // Get the /24 (IPv4) or /64 (IPv6) subnet as a u64 key
            let subnet_key = match ip {
                IpAddr::V4(ip) => ipv4_subnet_key_u64(&ip),
                IpAddr::V6(ip) => ipv6_subnet_key_u64(&ip),
            };

            let allowed = rate_limit_table::check_and_record(
                shard,
                subnet_key,
                now,
                now_millis,
                max_per_period as u32,
                period,
                clear_frequency,
            )
            .await;

            if !allowed {
                return Err(ErrorTooManyRequests(
                    "Too many requests. Please try again later.",
                ));
            }

            req_fut.await
        })
    }
}

#[inline]
fn ipv4_subnet_key_u64(ip: &Ipv4Addr) -> u64 {
    u32::from_be_bytes([ip.octets()[0], ip.octets()[1], ip.octets()[2], 0]) as u64
}

#[inline]
fn ipv6_subnet_key_u64(ip: &Ipv6Addr) -> u64 {
    let segments = ip.segments();
    // Combine the first 4 segments (8 bytes) into a u64 (big-endian)
    ((segments[0] as u64) << 48)
        | ((segments[1] as u64) << 32)
        | ((segments[2] as u64) << 16)
        | (segments[3] as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};
    use tokio::time::sleep;

    #[actix_web::test]
    async fn test_limiter_ipv4() {
        let limiter = Limiter::new(2, Duration::from_millis(5), Duration::from_millis(8));

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Requests from different IPs in the same /24 subnet (127.0.0.0/24)
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.2"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        // Throw in a request from a different subnet (same table) to make sure it doesn't affect the limit
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.64.1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.99"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err()); // Should hit the limit for the subnet

        // Other IP in a different /24 subnet
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.1.1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        sleep(Duration::from_millis(5)).await;

        // Period has expired, so we should be able to make another request from the same subnet
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.3"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.4"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.5"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        sleep(Duration::from_millis(1)).await;

        // Period has not expired
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.6"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // Make a request from a new IP in a different subnet (and different table)
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.15.1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.7"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        sleep(Duration::from_millis(3)).await;

        // This request should trigger a clear (different subnet, same table)
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.32.1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        // Table has been cleared, so we should be able to make another request from the original subnet
        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.8"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.9"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "127.0.0.10"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());
    }

    #[actix_web::test]
    async fn test_limiter_ipv6() {
        let limiter = Limiter::new(2, Duration::from_millis(5), Duration::from_millis(8));

        let app =
            test::init_service(App::new().wrap(limiter).service(
                web::resource("/").to(|| async { HttpResponse::Ok().body("Hello world") }),
            ))
            .await;

        // Requests from different IPs in the same /64 subnet (b24c:089b:7a21:1aff::/64)
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::2"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        // Throw in a request from a different subnet (same table)to make sure it doesn't affect the limit
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1abf::2"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::abcd"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err()); // Should hit the limit for the subnet

        // Other IP in a different /64 subnet (change 4th segment)
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1bff::1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        sleep(Duration::from_millis(5)).await;

        // Period has expired, so we should be able to make another request from the same subnet
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::3"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::4"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::5"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        sleep(Duration::from_millis(1)).await;

        // Period has not expired
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::6"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // Make a request from a new IP in a different subnet (and different table)
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aee::1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::7"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        sleep(Duration::from_millis(3)).await;

        // This request should trigger the clear (different subnet, same table)
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1acf::1"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        // Table has been cleared, so we should be able to make another request from the original subnet
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::8"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::9"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff::a"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());
    }
}
