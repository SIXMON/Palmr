import { FastifyReply, FastifyRequest } from "fastify";

import { authCookieOptions } from "../../shared/cookies";
import { revokeJti } from "../../shared/jwt-revocation";
import { signSessionJwt } from "../../shared/jwt-sign";
import { ConfigService } from "../config/service";
import {
  CompleteTwoFactorLoginSchema,
  createResetPasswordSchema,
  LoginSchema,
  RequestPasswordResetSchema,
} from "./dto";
import { AuthService } from "./service";

export class AuthController {
  private authService = new AuthService();
  private configService = new ConfigService();

  private getClientInfo(request: FastifyRequest) {
    // Use Fastify's request.ip — with trustProxy enabled, it already honours
    // X-Forwarded-For from the configured proxy chain. Do NOT trust custom
    // x-real-ip / x-user-agent headers: any client can forge them, which would
    // let an attacker bypass the per-IP throttle and forge trusted-device
    // identifiers.
    const userAgent = (request.headers["user-agent"] as string | undefined) || "";
    const ipAddress = request.ip || request.socket.remoteAddress || "";
    return { userAgent, ipAddress };
  }

  async login(request: FastifyRequest, reply: FastifyReply) {
    try {
      const input = LoginSchema.parse(request.body);
      const { userAgent, ipAddress } = this.getClientInfo(request);
      const result = await this.authService.login(input, userAgent, ipAddress);

      if ("requiresTwoFactor" in result) {
        return reply.send(result);
      }

      const user = result;
      const token = await signSessionJwt(request, {
        userId: user.id,
        isAdmin: user.isAdmin,
      });

      reply.setCookie("token", token, authCookieOptions);

      return reply.send({ user });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async completeTwoFactorLogin(request: FastifyRequest, reply: FastifyReply) {
    try {
      const input = CompleteTwoFactorLoginSchema.parse(request.body);
      const { userAgent, ipAddress } = this.getClientInfo(request);
      const user = await this.authService.completeTwoFactorLogin(
        input.pre2faToken,
        input.token,
        input.rememberDevice,
        userAgent,
        ipAddress
      );

      const token = await signSessionJwt(request, {
        userId: user.id,
        isAdmin: user.isAdmin,
      });

      reply.setCookie("token", token, authCookieOptions);

      return reply.send({ user });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async logout(request: FastifyRequest, reply: FastifyReply) {
    // Best-effort: revoke the presented JWT's jti so further requests
    // carrying the same cookie/Authorization header are rejected even
    // before its natural expiry.
    try {
      await request.jwtVerify();
      const payload = (request as any).user;
      if (payload?.jti && typeof payload?.exp === "number") {
        revokeJti(payload.jti, payload.exp);
      }
    } catch {
      // No valid token — nothing to revoke; still clear the cookie below.
    }
    reply.clearCookie("token", { path: "/" });
    return reply.send({ message: "Logout successful" });
  }

  async requestPasswordReset(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { email } = RequestPasswordResetSchema.parse(request.body);
      await this.authService.requestPasswordReset(email);
      return reply.send({
        message: "If an account exists with this email, a password reset link will be sent.",
      });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async resetPassword(request: FastifyRequest, reply: FastifyReply) {
    try {
      const schema = await createResetPasswordSchema();
      const input = schema.parse(request.body);
      await this.authService.resetPassword(input.token, input.password);
      return reply.send({ message: "Password reset successfully" });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async getCurrentUser(request: FastifyRequest, reply: FastifyReply) {
    try {
      let userId: string | null = null;
      try {
        await request.jwtVerify();
        userId = (request as any).user?.userId;
      } catch (err) {
        return reply.send({ user: null });
      }

      if (!userId) {
        return reply.send({ user: null });
      }

      const user = await this.authService.getUserById(userId);
      if (!user) {
        return reply.send({ user: null });
      }

      return reply.send({ user });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async getTrustedDevices(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
      }

      const devices = await this.authService.getTrustedDevices(userId);
      return reply.send({ devices });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async removeTrustedDevice(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
      }

      const { id } = request.params as { id: string };
      await this.authService.removeTrustedDevice(userId, id);
      return reply.send({ success: true, message: "Trusted device removed successfully" });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async removeAllTrustedDevices(request: FastifyRequest, reply: FastifyReply) {
    try {
      const userId = (request as any).user?.userId;
      if (!userId) {
        return reply.status(401).send({ error: "Unauthorized: a valid token is required to access this resource." });
      }

      const result = await this.authService.removeAllTrustedDevices(userId);
      return reply.send(result);
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }

  async getAuthConfig(request: FastifyRequest, reply: FastifyReply) {
    try {
      const passwordAuthEnabled = await this.configService.getValue("passwordAuthEnabled");
      return reply.send({
        passwordAuthEnabled: passwordAuthEnabled === "true",
      });
    } catch (error: any) {
      return reply.status(400).send({ error: error.message });
    }
  }
}
