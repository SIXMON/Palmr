import type { FastifyRequest } from "fastify";

declare module "fastify" {
  interface FastifyRequest {
    /**
     * Decorated helper used to sign a JWT payload. Provided by app.ts.
     */
    jwtSign(payload: object, options?: object): string;
  }
}

/**
 * Type-augment the JWT payload shape so `request.user` is no longer `any`.
 * Every place that used `(request as any).user?.userId` can drop the cast.
 */
declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: { userId: string; isAdmin: boolean; jti?: string; exp?: number };
    user: { userId: string; isAdmin: boolean; jti?: string; exp?: number };
  }
}
