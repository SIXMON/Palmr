import { FastifyReply, FastifyRequest } from "fastify";

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

    if (!request.user?.isAdmin) {
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
    return (request as any).user?.userId ?? null;
  } catch {
    return null;
  }
}
