import crypto from "node:crypto";
import { FastifyRequest } from "fastify";

/**
 * Sign a session JWT with a unique `jti` so the token can later be revoked
 * via the in-memory blacklist (see jwt-revocation.ts).
 */
export async function signSessionJwt(
  request: FastifyRequest,
  payload: { userId: string; isAdmin: boolean }
): Promise<string> {
  const jti = crypto.randomUUID();
  return await (request as any).jwtSign({ ...payload, jti });
}
