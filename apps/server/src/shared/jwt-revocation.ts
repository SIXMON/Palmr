/**
 * In-memory blacklist of revoked JWT IDs.
 *
 * When a user logs out we add their token's `jti` here so any further request
 * presenting the same JWT is rejected even though it's still
 * cryptographically valid. Entries auto-expire after the JWT TTL so the
 * map cannot grow unbounded.
 *
 * Single-instance only; for multi-instance deployments back this with
 * Redis (SET jwt:revoked:<jti> "1" EX <ttl>).
 */

const revoked = new Map<string, number>(); // jti -> expiresAt epoch ms

const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [jti, exp] of revoked.entries()) {
    if (exp < now) revoked.delete(jti);
  }
}, CLEANUP_INTERVAL_MS).unref?.();

/**
 * Revoke a JWT id until its natural expiration. `expSeconds` is the JWT's
 * exp claim (seconds since epoch).
 */
export function revokeJti(jti: string, expSeconds: number): void {
  revoked.set(jti, expSeconds * 1000);
}

export function isJtiRevoked(jti: string | undefined): boolean {
  if (!jti) return false;
  const exp = revoked.get(jti);
  if (!exp) return false;
  if (exp < Date.now()) {
    revoked.delete(jti);
    return false;
  }
  return true;
}
