/**
 * Bcrypt cost factor for password and secret hashing.
 *
 * OWASP 2024 minimum is 12. Higher is better but the cost is exponential;
 * 12 keeps a single hash under ~250 ms on modern hardware while staying ~4x
 * stronger than the previous default of 10. Configurable via env so ops can
 * raise it without a code change.
 */
const parsed = Number(process.env.BCRYPT_COST);
export const BCRYPT_COST = Number.isInteger(parsed) && parsed >= 10 && parsed <= 16 ? parsed : 12;
