import type { FastifyRequest } from "fastify";

/**
 * Resolve the share password from a request, accepting both:
 *   - querystring `?password=...` (works for browser navigation and OpenAPI clients)
 *   - header `X-Share-Password: ...` (used by the web client so the secret
 *     doesn't show up in browser history / proxy logs)
 *
 * The frontend currently sends the password as the header form, but the
 * earlier backend implementation only looked at the querystring — which made
 * authenticated downloads fail with a confusing 401 even after the user had
 * already entered the share password.
 */
export function getSharePassword(request: FastifyRequest): string | undefined {
  const fromQuery = (request.query as { password?: unknown } | undefined)?.password;
  if (typeof fromQuery === "string" && fromQuery.length > 0) {
    return fromQuery;
  }

  const headerRaw = request.headers["x-share-password"];
  if (typeof headerRaw === "string" && headerRaw.length > 0) {
    return headerRaw;
  }
  // Fastify normalises to lowercase but defensively check the array form too.
  if (Array.isArray(headerRaw) && headerRaw[0] && typeof headerRaw[0] === "string") {
    return headerRaw[0];
  }

  return undefined;
}
