import { FastifyReply, FastifyRequest } from "fastify";

import { StorageService } from "./service";

export class StorageController {
  private storageService = new StorageService();

  async getDiskSpace(request: FastifyRequest, reply: FastifyReply) {
    try {
      let userId: string | undefined;
      let isAdmin = false;

      try {
        await request.jwtVerify();
        userId = (request as any).user?.userId;
        isAdmin = (request as any).user?.isAdmin || false;
      } catch (err) {
        return reply.status(401).send({
          error: "Unauthorized: a valid token is required to access this resource.",
        });
      }

      const diskSpace = await this.storageService.getDiskSpace(userId, isAdmin);
      return reply.send(diskSpace);
    } catch (error: any) {
      console.error("Controller error in getDiskSpace:", error);

      // Never leak error.message to the client — it may contain absolute
      // paths, mount info, or stack fragments. Use opaque, code-tagged
      // responses instead.
      if (error.message?.includes("Unable to determine actual disk space")) {
        return reply.status(503).send({
          error: "Disk space detection unavailable",
          code: "DISK_SPACE_DETECTION_FAILED",
        });
      }

      return reply.status(500).send({
        error: "Failed to retrieve disk space information",
      });
    }
  }

  async checkUploadAllowed(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { fileSize } = request.query as { fileSize: string };
      let userId: string | undefined;

      try {
        await request.jwtVerify();
        userId = (request as any).user?.userId;
      } catch (err) {
        return reply.status(401).send({
          error: "Unauthorized: a valid token is required to access this resource.",
        });
      }

      if (!fileSize) {
        return reply.status(400).send({
          error: "File size parameter is required (in bytes)",
        });
      }

      const sizeNumber = Number(fileSize);
      if (!Number.isFinite(sizeNumber) || sizeNumber < 0) {
        return reply.status(400).send({ error: "Invalid fileSize parameter" });
      }

      const result = await this.storageService.checkUploadAllowed(sizeNumber, userId);
      return reply.send(result);
    } catch (error: any) {
      console.error("Controller error in checkUploadAllowed:", error);
      return reply.status(500).send({ error: "Failed to check upload eligibility" });
    }
  }
}
