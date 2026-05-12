/**
 * S3 Storage Controller (Simplified)
 *
 * Auth-protected wrappers around the S3 storage provider.
 * Every endpoint enforces that the supplied objectName starts with the
 * caller's `<userId>/` prefix to prevent IDOR / object overwrite attacks.
 */

import { FastifyReply, FastifyRequest } from "fastify";

import { S3StorageProvider } from "../../providers/s3-storage.provider";

function getUserIdOrReply(request: FastifyRequest, reply: FastifyReply): string | null {
  const userId = (request as any).user?.userId as string | undefined;
  if (!userId) {
    reply.status(401).send({ error: "Unauthorized" });
    return null;
  }
  return userId;
}

function assertOwnsObject(userId: string, objectName: string, reply: FastifyReply): boolean {
  if (!objectName || objectName.includes("..") || !objectName.startsWith(`${userId}/`)) {
    reply.status(403).send({ error: "Access denied for this objectName" });
    return false;
  }
  return true;
}

export class S3StorageController {
  private storageProvider = new S3StorageProvider();

  async getUploadUrl(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = getUserIdOrReply(request, reply);
      if (!userId) return;

      const { objectName, expires } = request.body as { objectName: string; expires?: number };

      if (!objectName) {
        return reply.status(400).send({ error: "objectName is required" });
      }
      if (!assertOwnsObject(userId, objectName, reply)) return;

      const expiresIn = expires || 3600;

      const { isInternalStorage } = await import("../../config/storage.config.js");

      let uploadUrl: string;
      if (isInternalStorage) {
        uploadUrl = `/api/files/upload?objectName=${encodeURIComponent(objectName)}`;
      } else {
        uploadUrl = await this.storageProvider.getPresignedPutUrl(objectName, expiresIn);
      }

      return reply.status(200).send({
        uploadUrl,
        objectName,
        expiresIn,
        message: isInternalStorage ? "Upload via backend proxy" : "Upload directly to this URL using PUT request",
      });
    } catch (error) {
      console.error("[S3] Error generating upload URL:", error);
      return reply.status(500).send({ error: "Failed to generate upload URL" });
    }
  }

  async getDownloadUrl(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = getUserIdOrReply(request, reply);
      if (!userId) return;

      const { objectName, expires, fileName } = request.query as {
        objectName: string;
        expires?: string;
        fileName?: string;
      };

      if (!objectName) {
        return reply.status(400).send({ error: "objectName is required" });
      }
      if (!assertOwnsObject(userId, objectName, reply)) return;

      const exists = await this.storageProvider.fileExists(objectName);
      if (!exists) {
        return reply.status(404).send({ error: "File not found" });
      }

      const expiresIn = expires ? parseInt(expires, 10) : 3600;

      const { isInternalStorage } = await import("../../config/storage.config.js");

      let downloadUrl: string;
      if (isInternalStorage) {
        downloadUrl = `/api/files/download?objectName=${encodeURIComponent(objectName)}`;
      } else {
        downloadUrl = await this.storageProvider.getPresignedGetUrl(objectName, expiresIn, fileName);
      }

      return reply.status(200).send({
        downloadUrl,
        objectName,
        expiresIn,
        message: isInternalStorage ? "Download via backend proxy" : "Download directly from this URL",
      });
    } catch (error) {
      console.error("[S3] Error generating download URL:", error);
      return reply.status(500).send({ error: "Failed to generate download URL" });
    }
  }

  async upload(request: FastifyRequest, reply: FastifyReply) {
    return reply.status(501).send({
      error: "Not implemented",
      message: "Use getUploadUrl endpoint for efficient uploads",
    });
  }

  async deleteObject(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = getUserIdOrReply(request, reply);
      if (!userId) return;

      const { objectName } = request.params as { objectName: string };

      if (!objectName) {
        return reply.status(400).send({ error: "objectName is required" });
      }
      if (!assertOwnsObject(userId, objectName, reply)) return;

      await this.storageProvider.deleteObject(objectName);

      return reply.status(200).send({
        message: "Object deleted successfully",
        objectName,
      });
    } catch (error) {
      console.error("[S3] Error deleting object:", error);
      return reply.status(500).send({ error: "Failed to delete object" });
    }
  }

  async checkExists(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = getUserIdOrReply(request, reply);
      if (!userId) return;

      const { objectName } = request.query as { objectName: string };

      if (!objectName) {
        return reply.status(400).send({ error: "objectName is required" });
      }
      if (!assertOwnsObject(userId, objectName, reply)) return;

      const exists = await this.storageProvider.fileExists(objectName);

      return reply.status(200).send({
        exists,
        objectName,
      });
    } catch (error) {
      console.error("[S3] Error checking existence:", error);
      return reply.status(500).send({ error: "Failed to check existence" });
    }
  }
}
