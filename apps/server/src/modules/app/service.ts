import { prisma } from "../../shared/prisma";
import { ConfigService } from "../config/service";

export class AppService {
  private configService = new ConfigService();

  async getAppInfo() {
    const [appName, appDescription, appLogo, firstUserAccess] = await Promise.all([
      this.configService.getValue("appName"),
      this.configService.getValue("appDescription"),
      this.configService.getValue("appLogo"),
      this.configService.getValue("firstUserAccess"),
    ]);

    return {
      appName,
      appDescription,
      appLogo,
      firstUserAccess: firstUserAccess === "true",
    };
  }

  async getSystemInfo() {
    return {
      storageProvider: "s3",
      s3Enabled: true,
    };
  }

  async getAllConfigs() {
    return prisma.appConfig.findMany({
      where: {
        key: {
          not: "jwtSecret",
        },
      },
      orderBy: {
        group: "asc",
      },
    });
  }

  // Whitelist of config keys safe to return on the public, unauthenticated
  // /app/configs/public endpoint. Using a whitelist (not a blacklist) ensures
  // any newly added secret-bearing key does NOT leak by default.
  private static readonly PUBLIC_CONFIG_KEYS = [
    "appName",
    "appDescription",
    "appLogo",
    "showHomePage",
    "passwordAuthEnabled",
    "firstUserAccess",
    "maxFileSize",
    "maxTotalStoragePerUser",
    "passwordMinLength",
    "smtpEnabled",
  ];

  async getPublicConfigs() {
    return prisma.appConfig.findMany({
      where: {
        key: { in: AppService.PUBLIC_CONFIG_KEYS },
      },
      orderBy: {
        group: "asc",
      },
    });
  }

  /**
   * Per-key validation rules. Any key not present here is rejected as
   * "unknown / not editable" — including jwtSecret. Validators accept the
   * raw string and return the canonical string to persist (or throw).
   */
  private static readonly CONFIG_VALIDATORS: Record<string, (raw: string) => string> = {
    appName: (v) => AppService.assertNonEmptyString(v, "appName", 64),
    appDescription: (v) => AppService.assertOptionalString(v, "appDescription", 500),
    appLogo: (v) => AppService.assertOptionalUrl(v, "appLogo"),
    showHomePage: AppService.boolean,
    firstUserAccess: AppService.boolean,
    serverUrl: (v) => AppService.assertOptionalUrl(v, "serverUrl"),
    passwordAuthEnabled: AppService.boolean,
    maxLoginAttempts: (v) => AppService.intInRange(v, "maxLoginAttempts", 1, 100),
    loginBlockDuration: (v) => AppService.intInRange(v, "loginBlockDuration", 30, 24 * 60 * 60),
    passwordMinLength: (v) => AppService.intInRange(v, "passwordMinLength", 6, 128),
    passwordResetTokenExpiration: (v) => AppService.intInRange(v, "passwordResetTokenExpiration", 60, 24 * 60 * 60),
    maxFileSize: (v) => AppService.bigIntInRange(v, "maxFileSize", BigInt(1024), BigInt("10995116277760")),
    maxTotalStoragePerUser: (v) =>
      AppService.bigIntInRange(v, "maxTotalStoragePerUser", BigInt(1024 * 1024), BigInt("109951162777600")),
    smtpEnabled: AppService.boolean,
    smtpHost: (v) => AppService.assertOptionalString(v, "smtpHost", 255),
    smtpPort: (v) => AppService.intInRange(v, "smtpPort", 1, 65535),
    smtpUser: (v) => AppService.assertOptionalString(v, "smtpUser", 255),
    smtpPass: (v) => AppService.assertOptionalString(v, "smtpPass", 1024),
    smtpFromName: (v) => AppService.assertOptionalString(v, "smtpFromName", 100),
    smtpFromEmail: (v) => AppService.assertOptionalString(v, "smtpFromEmail", 255),
    smtpSecure: (v) => AppService.assertEnum(v, "smtpSecure", ["auto", "ssl", "tls", "none"]),
    smtpNoAuth: AppService.boolean,
    smtpTrustSelfSigned: AppService.boolean,
  };

  private static boolean(raw: string): string {
    if (raw !== "true" && raw !== "false") {
      throw new Error('Invalid boolean value (expected "true" or "false")');
    }
    return raw;
  }
  private static assertNonEmptyString(v: string, key: string, max: number): string {
    if (typeof v !== "string" || v.length === 0 || v.length > max) {
      throw new Error(`${key} must be a non-empty string (max ${max} chars)`);
    }
    return v;
  }
  private static assertOptionalString(v: string, key: string, max: number): string {
    if (typeof v !== "string" || v.length > max) {
      throw new Error(`${key} must be a string (max ${max} chars)`);
    }
    return v;
  }
  private static assertOptionalUrl(v: string, key: string): string {
    if (v.length === 0) return v;
    try {
      new URL(v);
    } catch {
      throw new Error(`${key} must be a valid URL`);
    }
    return v;
  }
  private static assertEnum(v: string, key: string, allowed: string[]): string {
    if (!allowed.includes(v)) {
      throw new Error(`${key} must be one of: ${allowed.join(", ")}`);
    }
    return v;
  }
  private static intInRange(v: string, key: string, min: number, max: number): string {
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max) {
      throw new Error(`${key} must be an integer between ${min} and ${max}`);
    }
    return String(n);
  }
  private static bigIntInRange(v: string, key: string, min: bigint, max: bigint): string {
    let n: bigint;
    try {
      n = BigInt(v);
    } catch {
      throw new Error(`${key} must be an integer`);
    }
    if (n < min || n > max) {
      throw new Error(`${key} must be between ${min} and ${max}`);
    }
    return n.toString();
  }

  private validateConfigUpdate(key: string, value: string): string {
    const validator = AppService.CONFIG_VALIDATORS[key];
    if (!validator) {
      // Unknown key: reject rather than blindly write. This also catches
      // jwtSecret (intentionally absent from the validators table).
      throw new Error(`Configuration "${key}" is not editable`);
    }
    return validator(value);
  }

  async updateConfig(key: string, value: string) {
    if (key === "passwordAuthEnabled" && value === "false") {
      const canDisable = await this.configService.validatePasswordAuthDisable();
      if (!canDisable) {
        throw new Error(
          "Password authentication cannot be disabled. At least one authentication provider must be active."
        );
      }
    }

    const canonical = this.validateConfigUpdate(key, value);

    const config = await prisma.appConfig.findUnique({
      where: { key },
    });

    if (!config) {
      throw new Error("Configuration not found");
    }

    // jwtSecret happens to be flagged isSystem; rejecting isSystem updates
    // here gives us a single chokepoint for "do not allow modifying this
    // row through the public config endpoint" beyond the allowlist above.
    if (config.isSystem && key === "jwtSecret") {
      throw new Error("JWT secret cannot be edited through this endpoint");
    }

    return prisma.appConfig.update({
      where: { key },
      data: { value: canonical },
    });
  }

  async bulkUpdateConfigs(updates: Array<{ key: string; value: string }>) {
    const passwordAuthUpdate = updates.find((update) => update.key === "passwordAuthEnabled");
    if (passwordAuthUpdate && passwordAuthUpdate.value === "false") {
      const canDisable = await this.configService.validatePasswordAuthDisable();
      if (!canDisable) {
        throw new Error(
          "Password authentication cannot be disabled. At least one authentication provider must be active."
        );
      }
    }

    const sanitized = updates.map((u) => ({ key: u.key, value: this.validateConfigUpdate(u.key, u.value) }));

    const keys = sanitized.map((update) => update.key);
    const existingConfigs = await prisma.appConfig.findMany({
      where: { key: { in: keys } },
    });

    if (existingConfigs.length !== keys.length) {
      const existingKeys = existingConfigs.map((config) => config.key);
      const missingKeys = keys.filter((key) => !existingKeys.includes(key));
      throw new Error(`Configurations not found: ${missingKeys.join(", ")}`);
    }

    return prisma.$transaction(
      sanitized.map((update) =>
        prisma.appConfig.update({
          where: { key: update.key },
          data: { value: update.value },
        })
      )
    );
  }
}
