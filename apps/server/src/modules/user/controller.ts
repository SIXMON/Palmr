import { FastifyReply, FastifyRequest } from "fastify";

import { authCookieOptions } from "../../shared/cookies";
import { replyWithError } from "../../shared/errors";
import { signSessionJwt } from "../../shared/jwt-sign";
import { AvatarService } from "./avatar.service";
import { createRegisterUserSchema, UpdateUserImageSchema, UpdateUserSchema } from "./dto";
import { UserService } from "./service";

export class UserController {
  private userService = new UserService();
  private avatarService = new AvatarService();

  async register(request: FastifyRequest, reply: FastifyReply) {
    try {
      const schema = await createRegisterUserSchema();
      const input = schema.parse(request.body);
      const user = await this.userService.register(input);

      // Auto-login the very first user (the bootstrap admin). Without this,
      // the frontend's post-register flow — which calls admin endpoints like
      // PATCH /app/configs/firstUserAccess to flip the bootstrap flag — would
      // hit 401 because requireAdmin only bypasses auth when usersCount===0,
      // and the freshly-created user has bumped the count to 1. Subsequent
      // /auth/register calls (admin-creating-other-admins) keep working as
      // before: requireAdmin runs, the caller's cookie is already there.
      if (user.isAdmin) {
        const token = await signSessionJwt(request, { userId: user.id, isAdmin: user.isAdmin });
        reply.setCookie("token", token, authCookieOptions);
      }

      return reply.status(201).send({ user, message: "User created successfully" });
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async listUsers(request: FastifyRequest, reply: FastifyReply) {
    try {
      const users = await this.userService.listUsers();
      return reply.send(users);
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async getUserById(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string };
      const user = await this.userService.getUserById(id);
      return reply.send(user);
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async updateUser(request: FastifyRequest, reply: FastifyReply) {
    try {
      const input = UpdateUserSchema.parse(request.body);
      // Strip isAdmin: privilege escalation must go through a dedicated route.
      const { id, isAdmin: _ignoredIsAdmin, ...updateData } = input;
      void _ignoredIsAdmin;
      const updatedUser = await this.userService.updateUser(id, updateData);
      return reply.send(updatedUser);
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async activateUser(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string };
      const user = await this.userService.activateUser(id);
      return reply.send(user);
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async deactivateUser(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string };
      const user = await this.userService.deactivateUser(id);
      return reply.send(user);
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async deleteUser(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string };
      const user = await this.userService.deleteUser(id);
      return reply.send(user);
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async updateUserImage(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string };
      const { image } = UpdateUserImageSchema.parse(request.body);
      const updatedUser = await this.userService.updateUser(id, { image });
      return reply.send(updatedUser);
    } catch (error) {
      return replyWithError(reply, error);
    }
  }

  async uploadAvatar(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized" });
      }

      const file = await request.file();
      if (!file) {
        return reply.status(400).send({ error: "No file uploaded" });
      }

      if (!file.mimetype.startsWith("image/")) {
        return reply.status(400).send({ error: "Only images are allowed" });
      }

      // Avatar files should be small (max 5MB), so we can safely use streaming to buffer
      const chunks: Buffer[] = [];
      const maxAvatarSize = 5 * 1024 * 1024; // 5MB
      let totalSize = 0;

      for await (const chunk of file.file) {
        totalSize += chunk.length;
        if (totalSize > maxAvatarSize) {
          throw new Error("Avatar file too large. Maximum size is 5MB.");
        }
        chunks.push(chunk);
      }

      const buffer = Buffer.concat(chunks);
      const base64Image = await this.avatarService.uploadAvatar(buffer);
      const updatedUser = await this.userService.updateUserImage(userId, base64Image);

      return reply.send(updatedUser);
    } catch (error) {
      console.error("Upload error:", error);
      return replyWithError(reply, error, "Failed to upload avatar");
    }
  }

  async removeAvatar(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized" });
      }

      await this.avatarService.deleteAvatar(userId);
      const updatedUser = await this.userService.getUserById(userId);
      return reply.send(updatedUser);
    } catch (error) {
      return replyWithError(reply, error, "Failed to remove avatar");
    }
  }
}
