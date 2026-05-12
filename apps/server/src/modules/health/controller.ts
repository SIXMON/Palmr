import { prisma } from "../../shared/prisma";

interface HealthReport {
  status: "healthy" | "degraded";
  timestamp: string;
  checks: {
    database: "up" | "down";
  };
}

/**
 * Probes the components the server is required to talk to so that an
 * orchestrator (Docker healthcheck, Kubernetes liveness probe, etc.) can
 * actually tell when we're broken. The previous implementation always
 * returned `status: healthy` regardless of whether the DB was reachable.
 *
 * S3 is intentionally NOT probed here:
 * - some deployments use a private bucket whose presigned-URL host isn't
 *   reachable from the API server's network namespace,
 * - probing on every healthcheck would add latency + cost.
 * S3 problems surface naturally on the first upload/download attempt.
 */
export class HealthController {
  async check(): Promise<HealthReport> {
    let database: "up" | "down" = "up";
    try {
      // Cheap round-trip query that doesn't care about schema specifics.
      await prisma.$queryRaw`SELECT 1`;
    } catch (err) {
      console.error("[health] database probe failed:", err);
      database = "down";
    }

    const status = database === "up" ? "healthy" : "degraded";
    return {
      status,
      timestamp: new Date().toISOString(),
      checks: { database },
    };
  }
}
