import crypto from "node:crypto";
import bcrypt from "bcryptjs";

import { prisma } from "../../shared/prisma";
import { ConfigService } from "../config/service";
import { EmailService } from "../email/service";
import { TwoFactorService } from "../two-factor/service";
import { UserResponseSchema } from "../user/dto";
import { PrismaUserRepository } from "../user/repository";
import { LoginInput } from "./dto";
import { TrustedDeviceService } from "./trusted-device.service";

const PRE_2FA_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function getJwtSecret(configService: ConfigService): Promise<string> {
  // Reuse the same JWT secret (env or db-persisted)
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  return await configService.getValue("jwtSecret");
}

function signPre2faToken(userId: string, secret: string): string {
  const payload = Buffer.from(
    JSON.stringify({ userId, exp: Date.now() + PRE_2FA_TOKEN_TTL_MS, scope: "pre-2fa" })
  ).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifyPre2faToken(token: string, secret: string): string | null {
  const [payload, sig] = (token || "").split(".");
  if (!payload || !sig) return null;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (decoded.scope !== "pre-2fa") return null;
    if (typeof decoded.exp !== "number" || decoded.exp < Date.now()) return null;
    if (typeof decoded.userId !== "string") return null;
    return decoded.userId;
  } catch {
    return null;
  }
}

export class AuthService {
  private userRepository = new PrismaUserRepository();
  private configService = new ConfigService();
  private emailService = new EmailService();
  private twoFactorService = new TwoFactorService();
  private trustedDeviceService = new TrustedDeviceService();

  async login(data: LoginInput, userAgent?: string, ipAddress?: string) {
    const passwordAuthEnabled = await this.configService.getValue("passwordAuthEnabled");
    if (passwordAuthEnabled === "false") {
      throw new Error("Password authentication is disabled. Please use an external authentication provider.");
    }

    const user = await this.userRepository.findUserByEmailOrUsername(data.emailOrUsername);
    if (!user) {
      throw new Error("Invalid credentials");
    }

    if (!user.isActive) {
      throw new Error("Account is inactive. Please contact an administrator.");
    }

    const maxAttempts = Number(await this.configService.getValue("maxLoginAttempts"));
    const blockDurationSeconds = Number(await this.configService.getValue("loginBlockDuration"));
    const blockDuration = blockDurationSeconds * 1000;

    const loginAttempt = await prisma.loginAttempt.findUnique({
      where: { userId: user.id },
    });

    if (loginAttempt) {
      if (loginAttempt.attempts >= maxAttempts && Date.now() - loginAttempt.lastAttempt.getTime() < blockDuration) {
        const remainingTime = Math.ceil(
          (blockDuration - (Date.now() - loginAttempt.lastAttempt.getTime())) / 1000 / 60
        );
        throw new Error(`Too many failed attempts. Please try again in ${remainingTime} minutes.`);
      }

      if (Date.now() - loginAttempt.lastAttempt.getTime() >= blockDuration) {
        await prisma.loginAttempt.delete({
          where: { userId: user.id },
        });
      }
    }

    if (!user.password) {
      throw new Error("This account uses external authentication. Please use the appropriate login method.");
    }

    const isValid = await bcrypt.compare(data.password, user.password);

    if (!isValid) {
      await prisma.loginAttempt.upsert({
        where: { userId: user.id },
        create: {
          userId: user.id,
          attempts: 1,
          lastAttempt: new Date(),
        },
        update: {
          attempts: {
            increment: 1,
          },
          lastAttempt: new Date(),
        },
      });

      throw new Error("Invalid credentials");
    }

    if (loginAttempt) {
      await prisma.loginAttempt.delete({
        where: { userId: user.id },
      });
    }

    const has2FA = await this.twoFactorService.isEnabled(user.id);

    if (has2FA) {
      if (userAgent && ipAddress) {
        const isDeviceTrusted = await this.trustedDeviceService.isDeviceTrusted(user.id, userAgent, ipAddress);
        if (isDeviceTrusted) {
          // Update last used timestamp for trusted device
          await this.trustedDeviceService.updateLastUsed(user.id, userAgent, ipAddress);
          return UserResponseSchema.parse(user);
        }
      }

      const jwtSecret = await getJwtSecret(this.configService);
      const pre2faToken = signPre2faToken(user.id, jwtSecret);
      return {
        requiresTwoFactor: true,
        pre2faToken,
        message: "Two-factor authentication required",
      };
    }

    return UserResponseSchema.parse(user);
  }

  async completeTwoFactorLogin(
    pre2faToken: string,
    token: string,
    rememberDevice: boolean = false,
    userAgent?: string,
    ipAddress?: string
  ) {
    // CRITICAL: require a server-signed pre-2fa token that proves the password
    // step succeeded. Without this, /2fa/login can be brute-forced with a
    // raw userId guess and 10^6 code attempts.
    const jwtSecret = await getJwtSecret(this.configService);
    const userId = verifyPre2faToken(pre2faToken, jwtSecret);
    if (!userId) {
      throw new Error("Invalid or expired two-factor session. Please log in again.");
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new Error("User not found");
    }

    if (!user.isActive) {
      throw new Error("Account is inactive. Please contact an administrator.");
    }

    // CRITICAL: count 2FA attempts so this endpoint can't be brute-forced.
    // The throttle reuses the same login_attempts row as password login.
    const maxAttempts = Number(await this.configService.getValue("maxLoginAttempts"));
    const blockDurationSeconds = Number(await this.configService.getValue("loginBlockDuration"));
    const blockDuration = blockDurationSeconds * 1000;
    const existing = await prisma.loginAttempt.findUnique({ where: { userId } });
    if (existing && existing.attempts >= maxAttempts && Date.now() - existing.lastAttempt.getTime() < blockDuration) {
      const remainingTime = Math.ceil((blockDuration - (Date.now() - existing.lastAttempt.getTime())) / 1000 / 60);
      throw new Error(`Too many failed attempts. Please try again in ${remainingTime} minutes.`);
    }

    const verificationResult = await this.twoFactorService.verifyToken(userId, token);

    if (!verificationResult.success) {
      await prisma.loginAttempt.upsert({
        where: { userId },
        create: { userId, attempts: 1, lastAttempt: new Date() },
        update: { attempts: { increment: 1 }, lastAttempt: new Date() },
      });
      throw new Error("Invalid two-factor authentication code");
    }

    await prisma.loginAttempt.deleteMany({
      where: { userId },
    });

    if (rememberDevice && userAgent && ipAddress) {
      await this.trustedDeviceService.addTrustedDevice(userId, userAgent, ipAddress);
    } else if (userAgent && ipAddress) {
      // Update last used timestamp if this is already a trusted device
      const isDeviceTrusted = await this.trustedDeviceService.isDeviceTrusted(userId, userAgent, ipAddress);
      if (isDeviceTrusted) {
        await this.trustedDeviceService.updateLastUsed(userId, userAgent, ipAddress);
      }
    }

    return UserResponseSchema.parse(user);
  }

  async requestPasswordReset(email: string) {
    const passwordAuthEnabled = await this.configService.getValue("passwordAuthEnabled");
    if (passwordAuthEnabled === "false") {
      throw new Error("Password authentication is disabled. Password reset is not available.");
    }

    const user = await this.userRepository.findUserByEmail(email);
    if (!user || !user.isActive) {
      // Always return success-shape to avoid user enumeration; do nothing if no user.
      return;
    }

    const token = crypto.randomBytes(128).toString("hex");
    const expirationSeconds = Number(await this.configService.getValue("passwordResetTokenExpiration"));

    await prisma.passwordReset.create({
      data: {
        userId: user.id,
        token,
        expiresAt: new Date(Date.now() + expirationSeconds * 1000),
      },
    });

    // CRITICAL: the reset URL must come from server-side config, never from
    // a client-supplied "origin" — otherwise an attacker can steal the token.
    const serverUrl = (await this.configService.getValue("serverUrl")) || "http://localhost:3333";
    const resetUrl = `${serverUrl.replace(/\/$/, "")}/reset-password?token=${token}`;

    try {
      await this.emailService.sendPasswordResetEmail(email, resetUrl, expirationSeconds);
    } catch (error) {
      console.error("Failed to send password reset email:", error);
      throw new Error("Failed to send password reset email");
    }
  }

  async resetPassword(token: string, newPassword: string) {
    const passwordAuthEnabled = await this.configService.getValue("passwordAuthEnabled");
    if (passwordAuthEnabled === "false") {
      throw new Error("Password authentication is disabled. Password reset is not available.");
    }

    const resetRequest = await prisma.passwordReset.findFirst({
      where: {
        token,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: true,
      },
    });

    if (!resetRequest) {
      throw new Error("Invalid or expired reset token");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.$transaction([
      prisma.user.update({
        where: { id: resetRequest.userId },
        data: { password: hashedPassword },
      }),
      prisma.passwordReset.update({
        where: { id: resetRequest.id },
        data: { used: true },
      }),
    ]);
  }

  async getUserById(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new Error("User not found");
    }
    return UserResponseSchema.parse(user);
  }

  async getTrustedDevices(userId: string) {
    return await this.trustedDeviceService.getUserTrustedDevices(userId);
  }

  async removeTrustedDevice(userId: string, deviceId: string) {
    return await this.trustedDeviceService.removeTrustedDevice(userId, deviceId);
  }

  async removeAllTrustedDevices(userId: string) {
    const result = await this.trustedDeviceService.removeAllTrustedDevices(userId);
    return {
      success: true,
      message: "All trusted devices removed successfully",
      removedCount: result.count,
    };
  }
}
