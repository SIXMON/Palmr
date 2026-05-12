import crypto from "node:crypto";

import { prisma } from "../../shared/prisma";
import { ConfigService } from "../config/service";

/**
 * Trusted-device identity.
 *
 * The hash is an HMAC-SHA256(secret, `${userId}|${userAgent}|${ipAddress}`):
 *   - secret prevents an attacker who knows UA+IP from forging the hash.
 *   - userId scopes the hash so two users behind the same NAT cannot collide
 *     onto each other's trusted-device row (which previously leaked
 *     IP/UA/lastUsedAt between users due to the global @@unique constraint).
 *
 * The unique key is `[userId, deviceHash]` (see schema.prisma).
 */
export class TrustedDeviceService {
  private configService = new ConfigService();
  private secretCache: string | null = null;

  private async getSecret(): Promise<string> {
    if (this.secretCache) return this.secretCache;
    if (process.env.JWT_SECRET) {
      // Reuse JWT_SECRET as keying material — different KDF domain via the
      // HMAC input prefix so the two never collide.
      this.secretCache = process.env.JWT_SECRET;
      return this.secretCache;
    }
    this.secretCache = await this.configService.getValue("jwtSecret");
    return this.secretCache;
  }

  private async generateDeviceHash(userId: string, userAgent: string, ipAddress: string): Promise<string> {
    const secret = await this.getSecret();
    return crypto
      .createHmac("sha256", secret)
      .update(`trusted-device:${userId}|${userAgent}|${ipAddress}`)
      .digest("hex");
  }

  async isDeviceTrusted(userId: string, userAgent: string, ipAddress: string): Promise<boolean> {
    const deviceHash = await this.generateDeviceHash(userId, userAgent, ipAddress);

    const trustedDevice = await prisma.trustedDevice.findFirst({
      where: {
        userId,
        deviceHash,
        expiresAt: { gt: new Date() },
      },
    });

    return !!trustedDevice;
  }

  async addTrustedDevice(userId: string, userAgent: string, ipAddress: string, deviceName?: string): Promise<void> {
    const deviceHash = await this.generateDeviceHash(userId, userAgent, ipAddress);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

    await prisma.trustedDevice.upsert({
      where: {
        userId_deviceHash: { userId, deviceHash },
      },
      create: {
        userId,
        deviceHash,
        deviceName,
        userAgent,
        ipAddress,
        expiresAt,
        lastUsedAt: new Date(),
      },
      update: {
        expiresAt,
        userAgent,
        ipAddress,
        lastUsedAt: new Date(),
      },
    });
  }

  /**
   * Opportunistic cleanup of expired devices. Cheap (single DELETE) so we call
   * it whenever a user lists their devices — keeps the table from growing
   * unbounded without needing a separate scheduler.
   */
  async cleanupExpiredDevices(): Promise<void> {
    await prisma.trustedDevice.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });
  }

  async getUserTrustedDevices(userId: string) {
    await this.cleanupExpiredDevices();
    return prisma.trustedDevice.findMany({
      where: {
        userId,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: "desc" },
    });
  }

  async removeTrustedDevice(userId: string, deviceId: string): Promise<void> {
    await prisma.trustedDevice.deleteMany({
      where: {
        id: deviceId,
        userId,
      },
    });
  }

  async removeAllTrustedDevices(userId: string): Promise<{ count: number }> {
    const result = await prisma.trustedDevice.deleteMany({
      where: { userId },
    });
    return { count: result.count };
  }

  async updateLastUsed(userId: string, userAgent: string, ipAddress: string): Promise<void> {
    const deviceHash = await this.generateDeviceHash(userId, userAgent, ipAddress);

    await prisma.trustedDevice.updateMany({
      where: { userId, deviceHash },
      data: { lastUsedAt: new Date() },
    });
  }
}
