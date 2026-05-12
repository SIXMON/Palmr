import { FastifyReply, FastifyRequest } from "fastify";

import { isJtiRevoked } from "./jwt-revocation";
import { prisma } from "./prisma";

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
    return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
  }
  // Reject revoked JWTs (e.g. after explicit logout) even though they are
  // still cryptographically valid until exp.
  if (isJtiRevoked(request.user?.jti)) {
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
      return;
    }

    try {
      await request.jwtVerify();
    } catch {
      return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
    }

    if (isJtiRevoked(request.user?.jti)) {
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
    if (!dbUser || !dbUser.isActive) {
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
