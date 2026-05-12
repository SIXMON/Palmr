import { prisma } from "../../shared/prisma";

/**
 * Fallbacks for config keys that the rest of the app may read before the
 * seed has run (or after a row was accidentally deleted). Returning a
 * sensible default keeps the API alive instead of crashing every endpoint
 * that depends on it.
 */
const CONFIG_FALLBACKS: Record<string, string> = {
  appName: "Palmr",
  appDescription: "File transfer",
  appLogo: "",
  showHomePage: "true",
  firstUserAccess: "true",
  serverUrl: "http://localhost:3333",
  passwordAuthEnabled: "true",
  maxLoginAttempts: "5",
  loginBlockDuration: "900",
  passwordMinLength: "8",
  passwordResetTokenExpiration: "3600",
  maxFileSize: String(1024 * 1024 * 1024), // 1 GiB
  maxTotalStoragePerUser: String(BigInt(10) * BigInt(1024) * BigInt(1024) * BigInt(1024)), // 10 GiB
  smtpEnabled: "false",
  smtpSecure: "auto",
  smtpNoAuth: "false",
  smtpTrustSelfSigned: "false",
};

export class ConfigService {
  async getValue(key: string): Promise<string> {
    const config = await prisma.appConfig.findUnique({
      where: { key },
    });

    if (config) {
      return config.value;
    }

    // Graceful fallback for well-known keys. Throws only for truly unknown
    // keys so a missing seed row doesn't take the whole server down.
    if (key in CONFIG_FALLBACKS) {
      console.warn(`[config] "${key}" missing from app_configs — using built-in default`);
      return CONFIG_FALLBACKS[key];
    }

    throw new Error(`Configuration ${key} not found`);
  }

  async setValue(key: string, value: string): Promise<void> {
    await prisma.appConfig.update({
      where: { key },
      data: { value },
    });
  }

  async validatePasswordAuthDisable(): Promise<boolean> {
    const enabledProviders = await prisma.authProvider.findMany({
      where: { enabled: true },
    });

    return enabledProviders.length > 0;
  }

  async validateAllProvidersDisable(): Promise<boolean> {
    const passwordAuthEnabled = await this.getValue("passwordAuthEnabled");
    return passwordAuthEnabled === "true";
  }

  async getGroupConfigs(group: string) {
    const configs = await prisma.appConfig.findMany({
      where: { group },
    });

    return configs.reduce((acc, curr) => {
      let value: any = curr.value;

      switch (curr.type) {
        case "number":
          value = Number(value);
          break;
        case "boolean":
          value = value === "true";
          break;
        case "json":
          value = JSON.parse(value);
          break;
        case "bigint":
          value = BigInt(value);
          break;
      }

      return { ...acc, [curr.key]: value };
    }, {});
  }
}
