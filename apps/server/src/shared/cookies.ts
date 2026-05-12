import { env } from "../env";

const JWT_LIFETIME_SECONDS = 24 * 60 * 60; // 1 day, matches JWT expiresIn in app.ts

/**
 * Canonical options for the auth JWT cookie. Centralized so every issuing
 * code path (password login, 2FA, OIDC callback) uses identical attributes:
 *   - httpOnly, path "/"
 *   - secure in prod (SECURE_SITE=true)
 *   - sameSite always strict — relaxing it cross-site is unsafe given the
 *     cookie is the only auth credential the browser ever sends
 *   - maxAge matches JWT TTL so the browser stops sending it after expiry
 */
export const authCookieOptions = {
  httpOnly: true,
  path: "/",
  secure: env.SECURE_SITE === "true",
  sameSite: "strict" as const,
  maxAge: JWT_LIFETIME_SECONDS,
};
