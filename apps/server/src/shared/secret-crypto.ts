import crypto from "node:crypto";

import { ConfigService } from "../modules/config/service";

/**
 * Envelope-encrypt secrets (TOTP secret, etc.) stored at rest.
 *
 * Key material is derived from JWT_SECRET (or the persisted jwtSecret config)
 * via HKDF so the encryption key is a separate keying-domain from the JWT
 * signing key. Storage format:
 *
 *   v1:<base64(iv)>:<base64(ciphertext)>:<base64(authTag)>
 *
 * Backward-compat: values that don't start with the "v1:" prefix are treated
 * as plaintext (older 2FA secrets seeded before this change) and returned
 * unchanged on decrypt — callers can then re-encrypt them on next write.
 */

const PREFIX = "v1:";
let keyCache: Buffer | null = null;

async function getKeyMaterial(): Promise<string> {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const configService = new ConfigService();
  return await configService.getValue("jwtSecret");
}

async function getKey(): Promise<Buffer> {
  if (keyCache) return keyCache;
  const material = await getKeyMaterial();
  keyCache = Buffer.from(
    crypto.hkdfSync("sha256", Buffer.from(material), Buffer.alloc(0), "palmr-secret-crypto/v1", 32)
  );
  return keyCache;
}

export async function encryptSecret(plaintext: string): Promise<string> {
  const key = await getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("base64")}:${encrypted.toString("base64")}:${tag.toString("base64")}`;
}

export async function decryptSecret(value: string): Promise<string> {
  if (!value.startsWith(PREFIX)) {
    // Legacy plaintext secret — return as-is so the caller can still verify
    // it and re-encrypt at next write.
    return value;
  }
  const [, ivB64, ctB64, tagB64] = value.split(":");
  if (!ivB64 || !ctB64 || !tagB64) {
    throw new Error("Malformed encrypted secret");
  }
  const key = await getKey();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]);
  return decrypted.toString("utf8");
}
