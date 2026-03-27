use std::time::Instant;

/// A token bucket rate limiter.
///
/// Tokens refill at `rate` per second up to `capacity` (burst ceiling).
/// `try_consume` returns `true` if a token was available and consumed.
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            capacity: burst as f64,
            rate: rate_per_sec,
            last_refill: Instant::now(),
        }
    }

    /// Returns `true` if the action is allowed (a token was consumed).
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns `true` if the bucket is currently full (safe to evict from a shared map).
    pub fn is_full(&self) -> bool {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens + elapsed * self.rate >= self.capacity
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }
}
