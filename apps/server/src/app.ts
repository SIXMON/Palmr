import crypto from "node:crypto";
import * as http from "node:http";
import fastifyCookie from "@fastify/cookie";
import { fastifyCors } from "@fastify/cors";
import fastifyJwt from "@fastify/jwt";
import { fastifySwaggerUi } from "@fastify/swagger-ui";
import { fastify } from "fastify";
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from "fastify-type-provider-zod";

import { registerSwagger } from "./config/swagger.config";
import { envTimeoutOverrides } from "./config/timeout.config";
import { env } from "./env";
import { prisma } from "./shared/prisma";

async function resolveJwtSecret(): Promise<string> {
  if (env.JWT_SECRET) {
    return env.JWT_SECRET;
  }

  const existing = await prisma.appConfig.findUnique({ where: { key: "jwtSecret" } });
  if (existing?.value && existing.value.length >= 32) {
    return existing.value;
  }

  const generated = crypto.randomBytes(64).toString("hex");
  await prisma.appConfig.upsert({
    where: { key: "jwtSecret" },
    update: { value: generated },
    create: {
      key: "jwtSecret",
      value: generated,
      type: "text",
      group: "security",
      isSystem: true,
    },
  });
  console.warn(
    "[security] JWT_SECRET env not set — generated and persisted a secret in app_configs. " +
      "Set JWT_SECRET in environment for production deployments."
  );
  return generated;
}

function parseAllowedOrigins(raw: string | undefined): string[] | null {
  if (!raw) return null;
  return raw
    .split(",")
    .map((o) => o.trim())
    .filter((o) => o.length > 0);
}

export async function buildApp() {
  const JWT_SECRET = await resolveJwtSecret();

  const allowedOrigins = parseAllowedOrigins(env.CORS_ALLOWED_ORIGINS);
  const maxBodySizeBytes = Number(env.MAX_BODY_SIZE_MB) * 1024 * 1024;

  const app = fastify({
    ajv: {
      customOptions: {
        removeAdditional: false,
      },
    },
    logger: {
      level: "warn",
    },
    bodyLimit: maxBodySizeBytes,
    connectionTimeout: 0,
    keepAliveTimeout: envTimeoutOverrides.keepAliveTimeout,
    requestTimeout: envTimeoutOverrides.requestTimeout,
    trustProxy: true,
    maxParamLength: 500,
    onProtoPoisoning: "ignore",
    onConstructorPoisoning: "ignore",
    ignoreTrailingSlash: true,
    serverFactory: (handler: (req: any, res: any) => void) => {
      const server = http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {
        res.setTimeout(0);
        req.setTimeout(0);

        req.on("close", () => {
          if (typeof global !== "undefined" && global.gc) {
            setImmediate(() => global.gc!());
          }
        });

        handler(req, res);
      });

      server.maxHeadersCount = 0;
      server.timeout = 0;
      server.keepAliveTimeout = envTimeoutOverrides.keepAliveTimeout;
      server.headersTimeout = envTimeoutOverrides.keepAliveTimeout + 1000;

      return server;
    },
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  app.addSchema({
    $id: "dateFormat",
    type: "string",
    format: "date-time",
  });

  app.register(fastifyCors, {
    origin: allowedOrigins && allowedOrigins.length > 0 ? allowedOrigins : false,
    credentials: true,
  });

  if (!allowedOrigins || allowedOrigins.length === 0) {
    console.warn(
      "[security] CORS_ALLOWED_ORIGINS env not set — cross-origin requests are blocked. " +
        "Set CORS_ALLOWED_ORIGINS=https://your-frontend.com (comma-separated) to allow your frontend."
    );
  }

  app.register(fastifyCookie);
  app.register(fastifyJwt, {
    secret: JWT_SECRET,
    cookie: {
      cookieName: "token",
      signed: false,
    },
    sign: {
      expiresIn: "1d",
    },
  });

  app.decorateRequest("jwtSign", function (this: any, payload: object, options?: object) {
    return this.server.jwt.sign(payload, options);
  });

  registerSwagger(app);
  app.register(fastifySwaggerUi, {
    routePrefix: "/swagger",
  });

  app.register(require("@scalar/fastify-api-reference"), {
    routePrefix: "/docs",
    configuration: {
      theme: "deepSpace",
    },
  });

  return app;
}
