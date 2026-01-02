use std::{
    collections::HashMap,
    hash::Hash,
    sync::atomic::{AtomicU32, Ordering},
    sync::OnceLock,
    time::{Duration, Instant},
};

use tokio::sync::RwLock;

static START: OnceLock<Instant> = OnceLock::new();

/// Initialize the global process start timestamp used by `now_millis_u32()`.
#[inline]
pub fn init_start() {
    START.get_or_init(Instant::now);
}

/// Milliseconds since process start (wrapping u32).
///
/// Note: This is intentionally a `u32` to allow atomic reads/writes without extra overhead.
#[inline]
pub fn now_millis_u32() -> u32 {
    Instant::now()
        .duration_since(
            *START
                .get()
                .expect("utils::limiter_table::init_start() must be called first"),
        )
        .as_millis() as u32
}

#[derive(Debug)]
pub struct LimiterEntry {
    pub count: AtomicU32,
    pub first_access: AtomicU32, // milliseconds since process start
}

pub struct LimiterTable<K> {
    pub map: HashMap<K, LimiterEntry>,
    pub last_clear: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckAndRecordResult {
    Allowed,
    /// Request is blocked; contains the updated count (including this blocked attempt).
    Blocked {
        count: u32,
    },
}

impl<K> LimiterTable<K> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            last_clear: Instant::now(),
        }
    }
}

/// Create a leaked, `'static` set of 16 sharded tables.
pub fn new_sharded_tables_16<K>() -> &'static [RwLock<LimiterTable<K>>; 16] {
    Box::leak(Box::new(std::array::from_fn(|_| {
        RwLock::new(LimiterTable::new())
    })))
}

/// Check and record a hit against the given key in the selected shard.
///
/// Returns `true` if the hit is allowed (and records it), or `false` if the key has exceeded
/// `max_per_period` within `period`.
pub async fn check_and_record<K: Eq + Hash>(
    shard: &RwLock<LimiterTable<K>>,
    key: K,
    now: Instant,
    now_millis: u32,
    max_per_period: u32,
    period: Duration,
    clear_frequency: Duration,
) -> CheckAndRecordResult {
    let result = {
        // The read lock is intentionally scoped in this block to ensure it gets
        // dropped before the write lock is acquired.
        let table = shard.read().await;
        let entry = table.map.get(&key);

        if let Some(entry) = entry {
            let first_access_millis = entry.first_access.load(Ordering::Relaxed);
            let count = entry.count.load(Ordering::Relaxed);

            if now_millis.wrapping_sub(first_access_millis) > period.as_millis() as u32 {
                // Try to reset first_access and count. The race is acceptable. It is fine if
                // another thread resets one or both of these concurrently.
                entry.first_access.store(now_millis, Ordering::Relaxed);
                entry.count.store(1, Ordering::Relaxed);
                Some(CheckAndRecordResult::Allowed)
            } else if count >= max_per_period {
                // Still record the blocked attempt so callers can warn periodically
                // about sustained over-limit traffic.
                let prev = entry.count.fetch_add(1, Ordering::Relaxed);
                Some(CheckAndRecordResult::Blocked { count: prev + 1 })
            } else {
                entry.count.fetch_add(1, Ordering::Relaxed);
                Some(CheckAndRecordResult::Allowed)
            }
        } else {
            None
        }
    };

    if let Some(result) = result {
        return result;
    }

    {
        let mut table = shard.write().await;

        if now.duration_since(table.last_clear) >= clear_frequency {
            // Clear the table every so often to prevent it from growing too large
            table.map.clear();
            table.map.shrink_to_fit();
            table.last_clear = now;
        }

        table
            .map
            .entry(key)
            .and_modify(|entry| {
                // Was added by another thread before we acquired the lock; just increment the count
                entry.count.fetch_add(1, Ordering::Relaxed);
            })
            .or_insert_with(|| LimiterEntry {
                first_access: AtomicU32::new(now_millis),
                count: AtomicU32::new(1),
            });
    }

    CheckAndRecordResult::Allowed
}
