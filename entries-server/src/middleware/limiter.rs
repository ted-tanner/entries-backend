use std::{
    collections::HashMap,
    future::{ready, Ready},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorTooManyRequests,
};
use futures::future::LocalBoxFuture;
use tokio::sync::RwLock;

#[derive(Debug, Default)]
struct LimiterEntry {
    count: u64,
    first_access_usecs: u64,
}

struct LimiterTable {
    map: HashMap<IpAddr, Mutex<LimiterEntry>>,
    last_clear: SystemTime,
}

impl LimiterTable {
    fn new() -> Self {
        LimiterTable {
            map: HashMap::new(),
            last_clear: SystemTime::now(),
        }
    }
}

#[derive(Clone)]
pub struct Limiter {
    max_per_period: u64,
    period: Duration,
    clear_frequency: Duration,
    limiter_tables: &'static [RwLock<LimiterTable>; 16],
}

impl Limiter {
    /// Should be created on a single thread. Panics if period is greater than clear frequency.
    pub fn new(max_per_period: u64, period: Duration, clear_frequency: Duration) -> Self {
        if period > clear_frequency {
            panic!("Period cannot be greater than clear frequency");
        }

        let limiter_tables = Box::leak(Box::new([
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
            RwLock::new(LimiterTable::new()),
        ]));

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

    limiter_tables: &'static [RwLock<LimiterTable>; 16],
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
        let table = unsafe { self.limiter_tables.get_unchecked(table_index) };

        let req_fut = self.service.call(req);

        let max_per_period = self.max_per_period;
        let period = self.period;
        let clear_frequency = self.clear_frequency;

        Box::pin(async move {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Now should always be after the Unix epoch");
            let timestamp_usecs: u64 = timestamp
                .as_micros()
                .try_into()
                .expect("Unix timestamp in microseconds should fit in a u64");

            let now = SystemTime::now();

            // Get the /24 or /64 subnet of the IP
            let subnet = match ip {
                IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::new(
                    ip.octets()[0],
                    ip.octets()[1],
                    ip.octets()[2],
                    0,
                )),
                IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::new(
                    ip.segments()[0],
                    ip.segments()[1],
                    ip.segments()[2],
                    ip.segments()[3],
                    0,
                    0,
                    0,
                    0,
                )),
            };

            let found_subnet = {
                // The read lock is intentionally scoped in this block to ensure it gets
                // dropped before the write lock is acquired
                let table = table.read().await;
                let entry = table.map.get(&subnet);

                if let Some(entry) = entry {
                    let mut entry = entry.lock().expect("Lock should not be poisoned");
                    let first_access = UNIX_EPOCH + Duration::from_micros(entry.first_access_usecs);

                    if first_access + period < now {
                        entry.first_access_usecs = timestamp_usecs;
                        entry.count = 1;
                    } else {
                        if entry.count >= max_per_period {
                            return Err(ErrorTooManyRequests(
                                "Too many requests. Please try again later.",
                            ));
                        }

                        entry.count += 1;
                    }

                    true
                } else {
                    false
                }
            };

            if !found_subnet {
                let mut table = table.write().await;

                if now > table.last_clear + clear_frequency {
                    // Clear the table every so often to prevent it from growing too large
                    table.map.clear();
                    table.map.shrink_to_fit();
                    table.last_clear = SystemTime::now();
                }

                table
                    .map
                    .entry(subnet)
                    .and_modify(|entry| {
                        // Was added by another thread before we acquired the lock; just
                        // increment the count
                        entry.get_mut().expect("Lock should not be poisoned").count += 1;
                    })
                    .or_insert_with(|| {
                        Mutex::new(LimiterEntry {
                            first_access_usecs: timestamp_usecs,
                            count: 1,
                        })
                    });
            }

            req_fut.await
        })
    }
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
