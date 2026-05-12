import { FastifyInstance } from "fastify";
import { z } from "zod";

import { HealthController } from "./controller";

export async function healthRoutes(app: FastifyInstance) {
  const healthController = new HealthController();

  app.get(
    "/health",
    {
      schema: {
        tags: ["Health"],
        operationId: "checkHealth",
        summary: "Check API Health",
        description:
          "Returns the health status of the API. Returns 200 when every required dependency is reachable, 503 when at least one component is degraded so orchestrators can act on the response.",
        response: {
          200: z.object({
            status: z.enum(["healthy", "degraded"]).describe("The health status"),
            timestamp: z.string().describe("The timestamp of the health check"),
            checks: z.object({
              database: z.enum(["up", "down"]),
            }),
          }),
          503: z.object({
            status: z.enum(["healthy", "degraded"]),
            timestamp: z.string(),
            checks: z.object({
              database: z.enum(["up", "down"]),
            }),
          }),
        },
      },
    },
    async (_request, reply) => {
      const result = await healthController.check();
      const statusCode = result.status === "healthy" ? 200 : 503;
      return reply.status(statusCode).send(result);
    }
  );
}
