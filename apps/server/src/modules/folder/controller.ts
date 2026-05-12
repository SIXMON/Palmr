import { FastifyReply, FastifyRequest } from "fastify";

import { env } from "../../env";
import { prisma } from "../../shared/prisma";
import { ConfigService } from "../config/service";
import {
  CheckFolderSchema,
  ListFoldersSchema,
  MoveFolderSchema,
  RegisterFolderSchema,
  UpdateFolderSchema,
} from "./dto";
import { FolderService } from "./service";

export class FolderController {
  private folderService = new FolderService();
  private configService = new ConfigService();

  async registerFolder(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
      }

      const input = RegisterFolderSchema.parse(request.body);

      if (input.parentId) {
        const parentFolder = await prisma.folder.findFirst({
          where: { id: input.parentId, userId },
        });
        if (!parentFolder) {
          return reply.status(400).send({ error: "Parent folder not found or access denied" });
        }

        // Reject creating a folder deeper than MAX_FOLDER_DEPTH. Without
        // this, an attacker can create an unbounded parent chain that DoS's
        // recursive ops (calculateFolderSize, getAllFilesInFolder, etc.).
        const depth = await this.measureFolderDepth(input.parentId, userId);
        if (depth + 1 > FolderController.MAX_FOLDER_DEPTH) {
          return reply
            .status(400)
            .send({ error: `Folder nesting limit (${FolderController.MAX_FOLDER_DEPTH}) reached` });
        }
      }

      // Check for duplicates and auto-rename if necessary
      const { generateUniqueFolderName } = await import("../../utils/file-name-generator.js");
      const uniqueName = await generateUniqueFolderName(input.name, userId, input.parentId);

      const folderRecord = await prisma.folder.create({
        data: {
          name: uniqueName,
          description: input.description,
          objectName: input.objectName,
          parentId: input.parentId,
          userId,
        },
        include: {
          _count: {
            select: {
              files: true,
              children: true,
            },
          },
        },
      });

      const totalSize = await this.folderService.calculateFolderSize(folderRecord.id, userId);

      const folderResponse = {
        id: folderRecord.id,
        name: folderRecord.name,
        description: folderRecord.description,
        objectName: folderRecord.objectName,
        parentId: folderRecord.parentId,
        userId: folderRecord.userId,
        createdAt: folderRecord.createdAt,
        updatedAt: folderRecord.updatedAt,
        totalSize: totalSize.toString(),
        _count: folderRecord._count,
      };

      return reply.status(201).send({
        folder: folderResponse,
        message: "Folder registered successfully.",
      });
    } catch (error: any) {
      console.error("Error in registerFolder:", error);
      return reply.status(400).send({ error: error.message });
    }
  }

  async checkFolder(request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify();
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({
          error: "Unauthorized: a valid token is required to access this resource.",
          code: "unauthorized",
        });
      }

      const input = CheckFolderSchema.parse(request.body);

      if (input.name.length > 100) {
        return reply.status(400).send({
          code: "folderNameTooLong",
          error: "Folder name exceeds maximum length of 100 characters",
          details: "100",
        });
      }

      const existingFolder = await prisma.folder.findFirst({
        where: {
          name: input.name,
          parentId: input.parentId || null,
          userId,
        },
      });

      if (existingFolder) {
        return reply.status(400).send({
          error: "A folder with this name already exists in this location",
          code: "duplicateFolderName",
        });
      }

      return reply.status(201).send({
        message: "Folder checks succeeded.",
      });
    } catch (error: any) {
      console.error("Error in checkFolder:", error);
      return reply.status(400).send({ error: error.message });
    }
  }

  async listFolders(request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify();
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
      }

      const input = ListFoldersSchema.parse(request.query);
      const { parentId, recursive: recursiveStr } = input;
      const recursive = recursiveStr === "false" ? false : true;

      const targetParentId = parentId === "null" || parentId === "" || !parentId ? null : parentId;
      let folders: any[];

      if (recursive) {
        // recursive=true means "every descendant under targetParentId" — not
        // "every folder owned by the user". The previous implementation
        // ignored the parentId filter, which made the parameter misleading.
        const allUserFolders = await prisma.folder.findMany({
          where: { userId },
          include: {
            _count: {
              select: { files: true, children: true },
            },
          },
          orderBy: [{ name: "asc" }],
        });

        if (targetParentId === null) {
          folders = allUserFolders;
        } else {
          const childrenByParent = new Map<string | null, any[]>();
          for (const f of allUserFolders) {
            const arr = childrenByParent.get(f.parentId) ?? [];
            arr.push(f);
            childrenByParent.set(f.parentId, arr);
          }
          const collected: any[] = [];
          const stack = [targetParentId];
          const visited = new Set<string>();
          while (stack.length) {
            const pid = stack.pop()!;
            if (visited.has(pid)) continue;
            visited.add(pid);
            for (const child of childrenByParent.get(pid) ?? []) {
              collected.push(child);
              stack.push(child.id);
            }
          }
          folders = collected;
        }
      } else {
        // Get only direct children of specified parent
        folders = await prisma.folder.findMany({
          where: {
            userId,
            parentId: targetParentId,
          },
          include: {
            _count: {
              select: { files: true, children: true },
            },
          },
          orderBy: [{ name: "asc" }],
        });
      }

      const foldersResponse = await Promise.all(
        folders.map(async (folder) => {
          const totalSize = await this.folderService.calculateFolderSize(folder.id, userId);
          return {
            id: folder.id,
            name: folder.name,
            description: folder.description,
            objectName: folder.objectName,
            parentId: folder.parentId,
            userId: folder.userId,
            createdAt: folder.createdAt,
            updatedAt: folder.updatedAt,
            totalSize: totalSize.toString(),
            _count: folder._count,
          };
        })
      );

      return reply.send({ folders: foldersResponse });
    } catch (error: any) {
      console.error("Error in listFolders:", error);
      return reply.status(500).send({ error: error.message });
    }
  }

  async updateFolder(request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify();
      const { id } = request.params as { id: string };
      const userId = (request as any).user?.userId;

      if (!userId) {
        return reply.status(401).send({
          error: "Unauthorized: a valid token is required to access this resource.",
        });
      }

      const updateData = UpdateFolderSchema.parse(request.body);

      const folderRecord = await prisma.folder.findUnique({ where: { id } });

      if (!folderRecord) {
        return reply.status(404).send({ error: "Folder not found." });
      }

      if (folderRecord.userId !== userId) {
        return reply.status(403).send({ error: "Access denied." });
      }

      // If renaming the folder, check for duplicates and auto-rename if necessary
      if (updateData.name && updateData.name !== folderRecord.name) {
        const { generateUniqueFolderName } = await import("../../utils/file-name-generator.js");
        const uniqueName = await generateUniqueFolderName(updateData.name, userId, folderRecord.parentId, id);
        updateData.name = uniqueName;
      }

      const updatedFolder = await prisma.folder.update({
        where: { id },
        data: updateData,
        include: {
          _count: {
            select: {
              files: true,
              children: true,
            },
          },
        },
      });

      const totalSize = await this.folderService.calculateFolderSize(updatedFolder.id, userId);

      const folderResponse = {
        id: updatedFolder.id,
        name: updatedFolder.name,
        description: updatedFolder.description,
        objectName: updatedFolder.objectName,
        parentId: updatedFolder.parentId,
        userId: updatedFolder.userId,
        createdAt: updatedFolder.createdAt,
        updatedAt: updatedFolder.updatedAt,
        totalSize: totalSize.toString(),
        _count: updatedFolder._count,
      };

      return reply.send({
        folder: folderResponse,
        message: "Folder updated successfully.",
      });
    } catch (error: any) {
      console.error("Error in updateFolder:", error);
      return reply.status(400).send({ error: error.message });
    }
  }

  async moveFolder(request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify();
      const userId = (request as any).user?.userId;

      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
      }

      const { id } = request.params as { id: string };
      const body = request.body as any;

      const input = {
        parentId: body.parentId === undefined ? null : body.parentId,
      };

      const validatedInput = MoveFolderSchema.parse(input);

      const existingFolder = await prisma.folder.findFirst({
        where: { id, userId },
      });

      if (!existingFolder) {
        return reply.status(404).send({ error: "Folder not found." });
      }

      if (validatedInput.parentId) {
        const parentFolder = await prisma.folder.findFirst({
          where: { id: validatedInput.parentId, userId },
        });
        if (!parentFolder) {
          return reply.status(400).send({ error: "Parent folder not found or access denied" });
        }

        if (await this.isDescendantOf(validatedInput.parentId, id, userId)) {
          return reply.status(400).send({ error: "Cannot move a folder into itself or its subfolders" });
        }

        const parentDepth = await this.measureFolderDepth(validatedInput.parentId, userId);
        const movedSubtreeDepth = await this.measureSubtreeDepth(id, userId);
        if (parentDepth + 1 + movedSubtreeDepth > FolderController.MAX_FOLDER_DEPTH) {
          return reply
            .status(400)
            .send({ error: `Folder nesting limit (${FolderController.MAX_FOLDER_DEPTH}) reached` });
        }
      }

      const updatedFolder = await prisma.folder.update({
        where: { id },
        data: { parentId: validatedInput.parentId },
        include: {
          _count: {
            select: {
              files: true,
              children: true,
            },
          },
        },
      });

      const totalSize = await this.folderService.calculateFolderSize(updatedFolder.id, userId);

      const folderResponse = {
        id: updatedFolder.id,
        name: updatedFolder.name,
        description: updatedFolder.description,
        objectName: updatedFolder.objectName,
        parentId: updatedFolder.parentId,
        userId: updatedFolder.userId,
        createdAt: updatedFolder.createdAt,
        updatedAt: updatedFolder.updatedAt,
        totalSize: totalSize.toString(),
        _count: updatedFolder._count,
      };

      return reply.send({
        folder: folderResponse,
        message: "Folder moved successfully.",
      });
    } catch (error: any) {
      console.error("Error in moveFolder:", error);
      const statusCode = error.message === "Folder not found" ? 404 : 400;
      return reply.status(statusCode).send({ error: error.message });
    }
  }

  async deleteFolder(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string };
      if (!id) {
        return reply.status(400).send({ error: "The 'id' parameter is required." });
      }

      const folderRecord = await prisma.folder.findUnique({ where: { id } });
      if (!folderRecord) {
        return reply.status(404).send({ error: "Folder not found." });
      }

      const userId = (request as any).user?.userId;
      if (folderRecord.userId !== userId) {
        return reply.status(403).send({ error: "Access denied." });
      }

      // CRITICAL: Prisma cascade deletes DB rows only — without explicitly
      // removing each contained file's object from storage, the bucket
      // accumulates orphan blobs (storage leak / DoS vector).
      const allFiles = await this.folderService.getAllFilesInFolder(id, userId);
      for (const file of allFiles) {
        try {
          await this.folderService.deleteObject(file.objectName);
        } catch (err) {
          console.error(`Failed to delete object ${file.objectName} during folder cleanup:`, err);
        }
      }

      try {
        await this.folderService.deleteObject(folderRecord.objectName);
      } catch (err) {
        console.error(`Failed to delete folder placeholder ${folderRecord.objectName}:`, err);
      }

      await prisma.folder.delete({ where: { id } });

      return reply.send({ message: "Folder deleted successfully." });
    } catch (error) {
      console.error("Error in deleteFolder:", error);
      return reply.status(500).send({ error: "Internal server error." });
    }
  }

  /**
   * Walks the parent chain of `potentialDescendantId` and returns true if it
   * eventually reaches `ancestorId`. Guards against:
   *   - corrupted data (parent cycles) via a `visited` set
   *   - pathologically deep trees via MAX_DEPTH (also enforced at create time)
   */
  private async isDescendantOf(potentialDescendantId: string, ancestorId: string, userId: string): Promise<boolean> {
    let currentId: string | null = potentialDescendantId;
    const visited = new Set<string>();
    let steps = 0;

    while (currentId) {
      if (currentId === ancestorId) {
        return true;
      }
      if (visited.has(currentId)) {
        return false; // cycle in DB — defensive
      }
      visited.add(currentId);
      if (++steps > FolderController.MAX_FOLDER_DEPTH) {
        return false;
      }

      const folder: { parentId: string | null } | null = await prisma.folder.findFirst({
        where: { id: currentId, userId },
      });

      if (!folder) break;
      currentId = folder.parentId;
    }

    return false;
  }

  /** Depth from the folder up to a root parent (0 = root). */
  private async measureFolderDepth(folderId: string, userId: string): Promise<number> {
    let currentId: string | null = folderId;
    const visited = new Set<string>();
    let depth = 0;
    while (currentId) {
      if (visited.has(currentId)) break;
      visited.add(currentId);
      if (depth > FolderController.MAX_FOLDER_DEPTH) break;
      const folder: { parentId: string | null } | null = await prisma.folder.findFirst({
        where: { id: currentId, userId },
        select: { parentId: true },
      });
      if (!folder || !folder.parentId) break;
      currentId = folder.parentId;
      depth += 1;
    }
    return depth;
  }

  /** Depth of the deepest descendant under `folderId` (0 = leaf). */
  private async measureSubtreeDepth(folderId: string, userId: string): Promise<number> {
    const children = await prisma.folder.findMany({
      where: { parentId: folderId, userId },
      select: { id: true },
    });
    if (children.length === 0) return 0;
    let maxChild = 0;
    for (const c of children) {
      const d = await this.measureSubtreeDepth(c.id, userId);
      if (d > maxChild) maxChild = d;
    }
    return maxChild + 1;
  }

  static readonly MAX_FOLDER_DEPTH = 64;
}
