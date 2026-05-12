import { ConfigService } from "../config/service";

const configService = new ConfigService();

/**
 * Pre-validation hook: if the request body carries a `password` field,
 * enforce the configured minimum length. Apply on every route that accepts
 * a password from the client (register, update, reset, invite register).
 *
 * Signature uses `any` (rather than typed FastifyRequest/FastifyReply) so
 * typed-provider route handlers keep their Zod-inferred body types — see
 * shared/auth.ts for the same rationale.
 */
export async function validatePasswordMiddleware(request: any, reply: any) {
  const body = request.body as { password?: unknown } | null | undefined;
  if (!body || typeof body !== "object") return;
  const password = body.password;
  if (password === undefined || password === null) return;
  if (typeof password !== "string") {
    return reply.status(400).send({ error: "Password must be a string" });
  }

  const minLength = Number(await configService.getValue("passwordMinLength"));

  if (password.length < minLength) {
    return reply.status(400).send({
      error: `Password must be at least ${minLength} characters long`,
    });
  }
}
