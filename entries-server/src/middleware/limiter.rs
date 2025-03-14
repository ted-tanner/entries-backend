use std::{
    collections::HashMap,
    future::{ready, Ready},
    net::{IpAddr, SocketAddr},
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
        #[cfg(test)]
        let ip = {
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
        };

        // peer_addr() only returns None in a test
        #[cfg(not(test))]
        let ip = req.peer_addr().expect("Address should always be available");

        let (ip, final_octet) = match ip {
            SocketAddr::V4(ip) => {
                let ip = ip.ip();
                let final_octet = unsafe { *ip.octets().get_unchecked(3) };
                (IpAddr::V4(*ip), final_octet)
            }
            SocketAddr::V6(ip) => {
                let ip = ip.ip();
                let final_octet = unsafe { *ip.octets().get_unchecked(15) };
                (IpAddr::V6(*ip), final_octet)
            }
        };

        let table_index = (final_octet & 0x0F) as usize;
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

            let found_ip = {
                // The read lock is intentionally scoped in this block to ensure it gets
                // dropped before the write lock is acquired
                let table = table.read().await;
                let entry = table.map.get(&ip);

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

            if !found_ip {
                let mut table = table.write().await;

                if now > table.last_clear + clear_frequency {
                    // Clear the table every so often to prevent it from growing too large
                    table.map.clear();
                    table.map.shrink_to_fit();
                    table.last_clear = SystemTime::now();
                }

                table
                    .map
                    .entry(ip)
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

        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // Other IPs should still be able to make requests
        let req = test::TestRequest::default()
            .append_header(("test-ip", "192.167.0.5"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        sleep(Duration::from_millis(5)).await;

        // Period has expired, so we should be able to make another request
        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        sleep(Duration::from_millis(2)).await;

        // Period has not expired
        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // Make a request from a new IP a write is triggered, which will check if the table
        // needs to be cleared (which it does). The last 4 bits of the IP must equal
        // the last four bits of the blocked IP (127.0.0.1) to get the same table. Thus
        // "192.167.0.16" won't trigger the clear, but "192.167.0.17" will.
        let req = test::TestRequest::default()
            .append_header(("test-ip", "192.167.0.16"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // This request should trigger the clear
        let req = test::TestRequest::default()
            .append_header(("test-ip", "192.167.0.17"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        // Table has been cleared, so we should be able to make another request
        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default().to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default().to_request();
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

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // Other IPs should still be able to make requests
        let req = test::TestRequest::default()
            .append_header(("test-ip", "e2bc:2381:8996:c56a:892f:dd59:c64e:0041"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        sleep(Duration::from_millis(5)).await;

        // Period has expired, so we should be able to make another request
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        sleep(Duration::from_millis(2)).await;

        // Period has not expired
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // Make a request from a new IP a write is triggered, which will check if the table
        // needs to be cleared (which it does). The last 4 bits of the IP must equal
        // the last four bits of the blocked IP (b24c:089b:7a21:1aff:2d32:dec2:867d:563c) to
        // get the same table.
        let req = test::TestRequest::default()
            .append_header(("test-ip", "0e43:c469:88fd:9ee4:43b9:8d21:616a:0989"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());

        // This request should trigger the clear
        let req = test::TestRequest::default()
            .append_header(("test-ip", "785a:ae4f:4d1a:d3be:a8bf:e109:6355:6adc"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        // Table has been cleared, so we should be able to make another request
        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_ok());

        let req = test::TestRequest::default()
            .append_header(("test-ip", "b24c:089b:7a21:1aff:2d32:dec2:867d:563c"))
            .to_request();
        let res = app.call(req).await;
        assert!(res.is_err());
    }
}
