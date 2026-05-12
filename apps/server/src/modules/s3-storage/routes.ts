/**
 * S3 Storage Routes
 *
 * Simple routes for S3-based storage using presigned URLs.
 * All endpoints require authentication and ownership of the objectName
 * (which must be under `<userId>/...` prefix). For reverse-share uploads,
 * use the dedicated reverse-share routes instead.
 */

import { FastifyInstance } from "fastify";
import { z } from "zod";

import { requireAuth } from "../../shared/auth";
import { S3StorageController } from "./controller";

export async function s3StorageRoutes(app: FastifyInstance) {
  const controller = new S3StorageController();

  // Get presigned upload URL
  app.post(
    "/s3/upload-url",
    {
      preValidation: requireAuth,
      schema: {
        tags: ["S3 Storage"],
        operationId: "getS3UploadUrl",
        summary: "Get presigned URL for upload",
        description: "Returns a presigned URL that clients can use to upload directly to S3",
        body: z.object({
          objectName: z.string().describe("Object name/path in S3"),
          expires: z.number().optional().describe("URL expiration in seconds (default: 3600)"),
        }),
        response: {
          200: z.object({
            uploadUrl: z.string(),
            objectName: z.string(),
            expiresIn: z.number(),
            message: z.string(),
          }),
          400: z.object({ error: z.string() }),
          401: z.object({ error: z.string() }),
          403: z.object({ error: z.string() }),
        },
      },
    },
    controller.getUploadUrl.bind(controller)
  );

  // Get presigned download URL
  app.get(
    "/s3/download-url",
    {
      preValidation: requireAuth,
      schema: {
        tags: ["S3 Storage"],
        operationId: "getS3DownloadUrl",
        summary: "Get presigned URL for download",
        description: "Returns a presigned URL that clients can use to download directly from S3",
        querystring: z.object({
          objectName: z.string().describe("Object name/path in S3"),
          expires: z.string().optional().describe("URL expiration in seconds (default: 3600)"),
          fileName: z.string().optional().describe("Optional filename for download"),
        }),
        response: {
          200: z.object({
            downloadUrl: z.string(),
            objectName: z.string(),
            expiresIn: z.number(),
            message: z.string(),
          }),
          400: z.object({ error: z.string() }),
          401: z.object({ error: z.string() }),
          403: z.object({ error: z.string() }),
          404: z.object({ error: z.string() }),
        },
      },
    },
    controller.getDownloadUrl.bind(controller)
  );

  // Delete object
  app.delete(
    "/s3/object/:objectName",
    {
      preValidation: requireAuth,
      schema: {
        tags: ["S3 Storage"],
        operationId: "deleteS3Object",
        summary: "Delete object from S3",
        params: z.object({
          objectName: z.string().describe("Object name/path in S3"),
        }),
        response: {
          200: z.object({
            message: z.string(),
            objectName: z.string(),
          }),
          400: z.object({ error: z.string() }),
          401: z.object({ error: z.string() }),
          403: z.object({ error: z.string() }),
          404: z.object({ error: z.string() }),
        },
      },
    },
    controller.deleteObject.bind(controller)
  );

  // Check if object exists
  app.get(
    "/s3/exists",
    {
      preValidation: requireAuth,
      schema: {
        tags: ["S3 Storage"],
        operationId: "checkS3ObjectExists",
        summary: "Check if object exists in S3",
        querystring: z.object({
          objectName: z.string().describe("Object name/path in S3"),
        }),
        response: {
          200: z.object({
            exists: z.boolean(),
            objectName: z.string(),
          }),
          400: z.object({ error: z.string() }),
          401: z.object({ error: z.string() }),
          403: z.object({ error: z.string() }),
        },
      },
    },
    controller.checkExists.bind(controller)
  );
}
