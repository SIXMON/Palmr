import { FastifyReply, FastifyRequest } from "fastify";

import { authCookieOptions } from "./cookies";
import { isJtiRevoked } from "./jwt-revocation";
import { prisma } from "./prisma";

/**
 * Tell the browser to drop the auth cookie. Used when we know the cookie
 * the browser sent is unusable (revoked, references a deleted user, etc) —
 * without this the browser keeps replaying the same dead cookie on every
 * subsequent request and the user gets stuck on a 401 loop until they
 * manually clear site data.
 *
 * Matches the path/sameSite/secure attributes of authCookieOptions so the
 * delete actually targets the right cookie.
 */
function clearAuthCookie(reply: any) {
  reply.clearCookie("token", {
    path: authCookieOptions.path,
    sameSite: authCookieOptions.sameSite,
    secure: authCookieOptions.secure,
  });
}

// NOTE: signatures use `any` (rather than typed FastifyRequest/FastifyReply)
// because typed-provider routes in this codebase infer request types from the
// Zod schema; tightening these hook signatures would break that inference for
// routes whose handlers depend on the inferred body/params types.

/**
 * Shared preValidation hook that requires a valid JWT.
 * Returns a 401 reply on failure — always `return reply.send(...)`
 * so Fastify doesn't continue to the route handler.
 */
export async function requireAuth(request: any, reply: any) {
  try {
    await request.jwtVerify();
  } catch {
    // The browser sent a token cookie that doesn't verify — clear it so the
    // next request retries with an empty cookie instead of looping on 401.
    if (request.cookies?.token) {
      clearAuthCookie(reply);
    }
    return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
  }
  // Reject revoked JWTs (e.g. after explicit logout) even though they are
  // still cryptographically valid until exp.
  if (isJtiRevoked(request.user?.jti)) {
    clearAuthCookie(reply);
    return reply.status(401).send({ error: "Session expired. Please log in again." });
  }
}

/**
 * Shared preValidation hook that requires admin privileges.
 * Bypasses auth only when no users exist yet (initial setup), to allow the
 * first user to be created. Once at least one user exists, full admin auth
 * is enforced regardless of count.
 */
export async function requireAdmin(request: any, reply: any) {
  try {
    const usersCount = await prisma.user.count();
    if (usersCount === 0) {
      // Bootstrap path. If the browser happens to be carrying a leftover
      // token from a previous instance, drop it on the way out so the
      // freshly issued first-admin cookie isn't shadowed by the old one.
      if (request.cookies?.token) {
        clearAuthCookie(reply);
      }
      return;
    }

    try {
      await request.jwtVerify();
    } catch {
      if (request.cookies?.token) {
        clearAuthCookie(reply);
      }
      return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
    }

    if (isJtiRevoked(request.user?.jti)) {
      clearAuthCookie(reply);
      return reply.status(401).send({ error: "Session expired. Please log in again." });
    }

    // Live re-check from the DB. The JWT carries isAdmin from the moment
    // the user logged in, so a demoted or deactivated admin would otherwise
    // keep admin access until their token naturally expires.
    const userId = request.user?.userId;
    if (!userId) {
      return reply.status(401).send({ error: "Unauthorized" });
    }
    const dbUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { isAdmin: true, isActive: true },
    });
    if (!dbUser) {
      // The JWT references a user that no longer exists in the DB (deleted
      // user, restored from backup, wiped dev DB, etc). Without clearing
      // the cookie here the browser keeps sending the dead token on every
      // request and the user is stuck in a 401 loop they can't recover
      // from without manually purging localStorage/cookies.
      clearAuthCookie(reply);
      return reply.status(401).send({ error: "Session expired. Please log in again." });
    }
    if (!dbUser.isActive) {
      clearAuthCookie(reply);
      return reply.status(401).send({ error: "Account is inactive" });
    }
    if (!dbUser.isAdmin) {
      return reply.status(403).send({ error: "Access restricted to administrators" });
    }
  } catch {
    return reply.status(500).send({ error: "Internal server error" });
  }
}

/**
 * Returns the userId from a verified JWT, or null if unauthenticated.
 * Use in routes that have auth-optional behavior (e.g. public share with optional auth).
 */
export async function tryGetUserId(request: FastifyRequest): Promise<string | null> {
  try {
    await request.jwtVerify();
    const user = (request as any).user;
    if (isJtiRevoked(user?.jti)) return null;
    return user?.userId ?? null;
  } catch {
    return null;
  }
}
