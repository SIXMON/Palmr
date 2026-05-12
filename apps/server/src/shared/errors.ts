import type { FastifyReply } from "fastify";
import { ZodError } from "zod";

/**
 * Map a thrown error to an HTTP status + opaque client message.
 *
 * - ZodError → 400 with a structured `details` payload (validation failures
 *   are safe to return — they describe the input, not internal state).
 * - Known "not found" / "unauthorized" / "expired" wording → mapped to
 *   appropriate status codes.
 * - Anything else → 500 with a generic message; the real error is logged
 *   server-side via `console.error` (callers should add context).
 *
 * The pattern across the codebase used to be
 *     catch (error: any) { return reply.status(400).send({ error: error.message }); }
 * which (a) leaks internal error text to the client and (b) miscodes
 * everything as 400. This helper centralises the right answer.
 */
export function replyWithError(reply: FastifyReply, error: unknown, fallbackMessage = "Internal server error") {
  if (error instanceof ZodError) {
    return reply.status(400).send({
      error: "Validation failed",
      details: error.errors.map((e) => ({ path: e.path.join("."), message: e.message })),
    });
  }

  if (error instanceof Error) {
    const msg = error.message || "";
    const lower = msg.toLowerCase();

    if (lower.includes("not found")) {
      return reply.status(404).send({ error: msg });
    }
    if (lower.includes("unauthorized") || lower.includes("invalid credentials") || lower.includes("invalid password")) {
      return reply.status(401).send({ error: msg });
    }
    if (lower.includes("forbidden") || lower.includes("access denied") || lower.includes("admin access required")) {
      return reply.status(403).send({ error: msg });
    }
    if (lower.includes("expired")) {
      return reply.status(410).send({ error: msg });
    }
    if (
      lower.includes("already exists") ||
      lower.includes("already registered") ||
      lower.includes("already been used") ||
      lower.includes("already enabled")
    ) {
      return reply.status(409).send({ error: msg });
    }
    if (
      lower.includes("too many") ||
      lower.includes("rate limit") ||
      lower.includes("maximum number") ||
      lower.includes("maximum allowed") ||
      lower.includes("max views")
    ) {
      return reply.status(429).send({ error: msg });
    }
    if (
      lower.includes("invalid") ||
      lower.includes("required") ||
      lower.includes("must be") ||
      lower.includes("exceeds") ||
      lower.includes("not allowed")
    ) {
      return reply.status(400).send({ error: msg });
    }
  }

  // Unknown error — log server-side, do not echo the message to the client.
  console.error("Unhandled controller error:", error);
  return reply.status(500).send({ error: fallbackMessage });
}
