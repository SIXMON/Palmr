/**
 * In-memory IP throttle for high-frequency auth endpoints (login, 2FA, invite
 * lookup). Single-instance only — for multi-instance deployments, swap the
 * backing store for Redis/Memcached.
 *
 * The throttle is intentionally simple: count failures per IP within a sliding
 * window. If count exceeds `max` within `windowMs`, every further attempt is
 * rejected until the window expires.
 */

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets.entries()) {
    if (bucket.resetAt < now) buckets.delete(key);
  }
}, CLEANUP_INTERVAL_MS).unref?.();

export interface IpRateLimitResult {
  blocked: boolean;
  retryAfterSeconds: number;
}

export function recordFailure(key: string, windowMs: number, max: number): IpRateLimitResult {
  const now = Date.now();
  const existing = buckets.get(key);
  if (!existing || existing.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { blocked: false, retryAfterSeconds: 0 };
  }
  existing.count += 1;
  if (existing.count > max) {
    return { blocked: true, retryAfterSeconds: Math.ceil((existing.resetAt - now) / 1000) };
  }
  return { blocked: false, retryAfterSeconds: 0 };
}

export function checkBlocked(key: string, max: number): IpRateLimitResult {
  const now = Date.now();
  const existing = buckets.get(key);
  if (!existing || existing.resetAt < now) {
    return { blocked: false, retryAfterSeconds: 0 };
  }
  if (existing.count >= max) {
    return { blocked: true, retryAfterSeconds: Math.ceil((existing.resetAt - now) / 1000) };
  }
  return { blocked: false, retryAfterSeconds: 0 };
}

export function clearKey(key: string): void {
  buckets.delete(key);
}
