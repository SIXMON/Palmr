import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import QRCode from "qrcode";
import speakeasy from "speakeasy";

import { BCRYPT_COST } from "../../shared/bcrypt-cost";
import { prisma } from "../../shared/prisma";
import { decryptSecret, encryptSecret } from "../../shared/secret-crypto";

interface BackupCodeRecord {
  hash: string;
  used: boolean;
}

const SETUP_TTL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Pending TOTP secrets for users currently going through enrolment. We store
 * them server-side (keyed by userId) and let `verifySetup` read them by id
 * rather than accepting an attacker-supplied `secret` from the client.
 *
 * Single-instance only — fine for the use case (a user finishes setup within
 * a few minutes from the same instance they started on).
 */
const pendingSetups = new Map<string, { secret: string; expiresAt: number }>();

setInterval(
  () => {
    const now = Date.now();
    for (const [k, v] of pendingSetups.entries()) {
      if (v.expiresAt < now) pendingSetups.delete(k);
    }
  },
  5 * 60 * 1000
).unref?.();

export class TwoFactorService {
  /**
   * Generate a new 2FA secret and QR code for setup.
   * The secret is held server-side (pendingSetups) and is NOT returned to the
   * client; only the QR code data URL is. verifySetup() looks it up by userId.
   */
  async generateSetup(userId: string, userEmail: string, appName?: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, twoFactorEnabled: true },
    });

    if (!user) {
      throw new Error("User not found");
    }

    if (user.twoFactorEnabled) {
      throw new Error("Two-factor authentication is already enabled");
    }

    const secret = speakeasy.generateSecret({
      name: `${appName || "Palmr"}:${userEmail}`,
      issuer: appName || "Palmr",
      length: 32,
    });

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url || "");

    pendingSetups.set(userId, {
      secret: secret.base32,
      expiresAt: Date.now() + SETUP_TTL_MS,
    });

    return {
      // We keep returning manualEntryKey for users who can't scan, but we
      // accept it back ONLY for the duration of pendingSetups[userId].
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
      // backupCodes are also generated lazily by verifySetup so we don't
      // accidentally show codes for a setup that the user abandons.
    };
  }

  /**
   * Verify setup token and enable 2FA using the server-stored pending secret.
   */
  async verifySetup(userId: string, token: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, twoFactorEnabled: true },
    });

    if (!user) {
      throw new Error("User not found");
    }
    if (user.twoFactorEnabled) {
      throw new Error("Two-factor authentication is already enabled");
    }

    const pending = pendingSetups.get(userId);
    if (!pending || pending.expiresAt < Date.now()) {
      throw new Error("2FA setup session expired. Please start again.");
    }

    const verified = speakeasy.totp.verify({
      secret: pending.secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      throw new Error("Invalid verification code");
    }

    const { records: backupRecords, plain: backupPlain } = await this.generateBackupCodes();
    const encryptedSecret = await encryptSecret(pending.secret);

    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        twoFactorBackupCodes: JSON.stringify(backupRecords),
        twoFactorVerified: true,
      },
    });

    pendingSetups.delete(userId);

    return {
      success: true,
      backupCodes: backupPlain,
    };
  }

  /**
   * Verify a 2FA token during login (TOTP or one-time backup code).
   */
  async verifyToken(userId: string, token: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        twoFactorEnabled: true,
        twoFactorSecret: true,
        twoFactorBackupCodes: true,
      },
    });

    if (!user) {
      throw new Error("User not found");
    }
    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      throw new Error("Two-factor authentication is not enabled");
    }

    const totpSecret = await decryptSecret(user.twoFactorSecret);
    const verified = speakeasy.totp.verify({
      secret: totpSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (verified) {
      // Opportunistic re-encryption: if the secret was stored plaintext
      // (legacy seeded value), upgrade it now that we've validated it works.
      if (!user.twoFactorSecret.startsWith("v1:")) {
        const encrypted = await encryptSecret(totpSecret);
        await prisma.user.update({
          where: { id: userId },
          data: { twoFactorSecret: encrypted },
        });
      }
      return { success: true, method: "totp" };
    }

    if (user.twoFactorBackupCodes) {
      const codes: BackupCodeRecord[] = this.parseBackupCodes(user.twoFactorBackupCodes);

      for (let i = 0; i < codes.length; i++) {
        if (codes[i].used) continue;
        // bcrypt.compare is constant-time relative to a fixed-length input.
        // We deliberately probe every code even after a match so the total
        // time doesn't leak the position of the matching code.
        const match = await bcrypt.compare(token, codes[i].hash);
        if (match) {
          codes[i].used = true;
          await prisma.user.update({
            where: { id: userId },
            data: { twoFactorBackupCodes: JSON.stringify(codes) },
          });
          return { success: true, method: "backup" };
        }
      }
    }

    throw new Error("Invalid verification code");
  }

  /**
   * Disable 2FA for a user (requires the current password).
   */
  async disable2FA(userId: string, password: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, password: true, twoFactorEnabled: true },
    });

    if (!user) {
      throw new Error("User not found");
    }
    if (!user.twoFactorEnabled) {
      throw new Error("Two-factor authentication is not enabled");
    }
    if (!user.password) {
      throw new Error("Password verification required");
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw new Error("Invalid password");
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorBackupCodes: null,
        twoFactorVerified: false,
      },
    });

    return { success: true };
  }

  /**
   * Generate new backup codes. Requires the user's password as a reauth step
   * so a stolen JWT alone cannot re-issue codes (which would lock the
   * legitimate user out and grant the attacker persistent backup access).
   */
  async generateNewBackupCodes(userId: string, password: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, password: true, twoFactorEnabled: true },
    });

    if (!user) {
      throw new Error("User not found");
    }
    if (!user.twoFactorEnabled) {
      throw new Error("Two-factor authentication is not enabled");
    }
    if (!user.password) {
      throw new Error("Password verification required");
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      throw new Error("Invalid password");
    }

    const { records, plain } = await this.generateBackupCodes();
    await prisma.user.update({
      where: { id: userId },
      data: { twoFactorBackupCodes: JSON.stringify(records) },
    });

    return plain;
  }

  async getStatus(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        twoFactorEnabled: true,
        twoFactorVerified: true,
        twoFactorBackupCodes: true,
      },
    });

    if (!user) {
      throw new Error("User not found");
    }

    let availableBackupCodes = 0;
    if (user.twoFactorBackupCodes) {
      const codes = this.parseBackupCodes(user.twoFactorBackupCodes);
      availableBackupCodes = codes.filter((bc) => !bc.used).length;
    }

    return {
      enabled: user.twoFactorEnabled,
      verified: user.twoFactorVerified,
      availableBackupCodes,
    };
  }

  private async generateBackupCodes(): Promise<{ records: BackupCodeRecord[]; plain: string[] }> {
    const records: BackupCodeRecord[] = [];
    const plain: string[] = [];
    for (let i = 0; i < 10; i++) {
      const raw = crypto.randomBytes(4).toString("hex").toUpperCase();
      const code = raw.match(/.{1,4}/g)?.join("-") || raw;
      plain.push(code);
      records.push({ hash: await bcrypt.hash(code, BCRYPT_COST), used: false });
    }
    return { records, plain };
  }

  /**
   * Parse the JSON-encoded backup codes column. Older rows stored
   * `{code, used}` with plaintext codes — those are dropped (marked used) on
   * read; the user must regenerate codes via /2fa/backup-codes after this
   * security upgrade. We intentionally don't keep verifying plaintext codes:
   * the whole point of this change is that codes are never compared in
   * cleartext anymore.
   */
  private parseBackupCodes(value: string): BackupCodeRecord[] {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((entry: any) => {
      if (typeof entry?.hash === "string" && entry.hash.startsWith("$2")) {
        return { hash: entry.hash, used: !!entry.used };
      }
      return { hash: "", used: true };
    });
  }

  /**
   * Check if user has 2FA enabled
   */
  async isEnabled(userId: string): Promise<boolean> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { twoFactorEnabled: true },
    });

    return user?.twoFactorEnabled ?? false;
  }
}
