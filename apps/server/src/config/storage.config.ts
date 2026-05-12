import * as fs from "fs";
import { Agent as HttpsAgent } from "node:https";
import { S3Client } from "@aws-sdk/client-s3";

import { env } from "../env";
import { StorageConfig } from "../types/storage";

/**
 * Load internal storage credentials if they exist
 * This provides S3-compatible storage automatically when ENABLE_S3=false
 */
function loadInternalStorageCredentials(): Partial<StorageConfig> | null {
  const credentialsPath = "/app/server/.minio-credentials";

  try {
    if (fs.existsSync(credentialsPath)) {
      const content = fs.readFileSync(credentialsPath, "utf-8");
      const credentials: any = {};

      content.split("\n").forEach((line) => {
        const [key, value] = line.split("=");
        if (key && value) {
          credentials[key.trim()] = value.trim();
        }
      });

      console.log("[STORAGE] Using internal storage system");

      return {
        endpoint: credentials.S3_ENDPOINT || "127.0.0.1",
        port: parseInt(credentials.S3_PORT || "9379", 10),
        useSSL: credentials.S3_USE_SSL === "true",
        accessKey: credentials.S3_ACCESS_KEY,
        secretKey: credentials.S3_SECRET_KEY,
        region: credentials.S3_REGION || "default",
        bucketName: credentials.S3_BUCKET_NAME || "palmr-files",
        forcePathStyle: true,
      };
    }
  } catch (error) {
    console.warn("[STORAGE] Could not load internal storage credentials:", error);
  }

  return null;
}

/**
 * Storage configuration:
 * - Default (ENABLE_S3=false or not set): Internal storage (auto-configured, zero config)
 * - ENABLE_S3=true: External S3 (AWS, S3-compatible, etc) using env vars
 */
const internalStorageConfig = env.ENABLE_S3 === "true" ? null : loadInternalStorageCredentials();

export const storageConfig: StorageConfig = (internalStorageConfig as StorageConfig) || {
  endpoint: env.S3_ENDPOINT || "",
  port: env.S3_PORT ? Number(env.S3_PORT) : undefined,
  useSSL: env.S3_USE_SSL === "true",
  accessKey: env.S3_ACCESS_KEY || "",
  secretKey: env.S3_SECRET_KEY || "",
  region: env.S3_REGION || "",
  bucketName: env.S3_BUCKET_NAME || "",
  forcePathStyle: env.S3_FORCE_PATH_STYLE === "true",
};

/**
 * Scope `S3_REJECT_UNAUTHORIZED=false` to the S3 client only, via a
 * dedicated httpsAgent. Setting NODE_TLS_REJECT_UNAUTHORIZED=0 globally
 * (the previous behaviour) disabled TLS verification for SMTP, OIDC,
 * webhooks — everything else this server might call.
 */
const allowSelfSignedS3 = storageConfig.useSSL && env.S3_REJECT_UNAUTHORIZED === "false";
const s3HttpsAgent = allowSelfSignedS3 ? new HttpsAgent({ rejectUnauthorized: false }) : undefined;

/**
 * Storage is ALWAYS S3-compatible:
 * - ENABLE_S3=false → Internal storage (automatic)
 * - ENABLE_S3=true  → External S3 (AWS, S3-compatible, etc)
 */
const hasValidConfig = storageConfig.endpoint && storageConfig.accessKey && storageConfig.secretKey;

const s3ClientConfig: any = {
  endpoint: storageConfig.useSSL
    ? `https://${storageConfig.endpoint}${storageConfig.port ? `:${storageConfig.port}` : ""}`
    : `http://${storageConfig.endpoint}${storageConfig.port ? `:${storageConfig.port}` : ""}`,
  region: storageConfig.region,
  credentials: {
    accessKeyId: storageConfig.accessKey,
    secretAccessKey: storageConfig.secretKey,
  },
  forcePathStyle: storageConfig.forcePathStyle,
  requestHandler: {
    requestTimeout: 300000, // 5 minutes timeout for S3 operations
    ...(s3HttpsAgent ? { httpsAgent: s3HttpsAgent } : {}),
  },
};

export const s3Client = hasValidConfig ? new S3Client(s3ClientConfig) : null;

export const bucketName = storageConfig.bucketName;

/**
 * Storage is always S3-compatible
 * ENABLE_S3=true means EXTERNAL S3, otherwise uses internal storage
 */
export const isS3Enabled = s3Client !== null;
export const isExternalS3 = env.ENABLE_S3 === "true";
export const isInternalStorage = s3Client !== null && env.ENABLE_S3 !== "true";

/**
 * Creates a public S3 client for presigned URL generation.
 *
 * The presigned URL goes to the BROWSER, so it must point at an endpoint
 * the browser can actually reach. That's almost never the same as the
 * server-side endpoint:
 *   - Internal storage (legacy monolithic image): server talks to MinIO on
 *     127.0.0.1:9379, browser needs an external URL → STORAGE_URL required.
 *   - Split-container setup: server talks to MinIO via the docker DNS name
 *     (e.g. `minio:9379`) — completely unreachable from outside the docker
 *     network. STORAGE_URL is required here too.
 *   - True external S3 (AWS, R2, etc.): the configured endpoint is already
 *     public, so STORAGE_URL is optional and we fall back to it.
 *
 * Previously this function only honoured STORAGE_URL when isInternalStorage
 * was true, which made the split compose hand out presigned URLs pointing
 * at `http://minio:9379/...` — fine for the server, useless for browsers.
 *
 * @returns S3Client configured with the public endpoint, or null if S3
 *          isn't configured at all.
 */
export function createPublicS3Client(): S3Client | null {
  if (!s3Client) {
    return null;
  }

  // Prefer STORAGE_URL whenever it's set — it always wins over the
  // server-side endpoint because it represents the browser's view.
  let publicEndpoint: string;
  if (env.STORAGE_URL) {
    publicEndpoint = env.STORAGE_URL;
  } else if (isInternalStorage) {
    throw new Error(
      "[STORAGE] STORAGE_URL environment variable is required when using internal storage (ENABLE_S3=false). " +
        "Set STORAGE_URL to your public storage URL with protocol (e.g., https://storage.example.com)."
    );
  } else {
    // True external S3 with no STORAGE_URL override: the original endpoint
    // is assumed to be reachable from the browser (the AWS case).
    publicEndpoint = storageConfig.useSSL
      ? `https://${storageConfig.endpoint}${storageConfig.port ? `:${storageConfig.port}` : ""}`
      : `http://${storageConfig.endpoint}${storageConfig.port ? `:${storageConfig.port}` : ""}`;
  }

  const publicConfig: any = {
    endpoint: publicEndpoint,
    region: storageConfig.region,
    credentials: {
      accessKeyId: storageConfig.accessKey,
      secretAccessKey: storageConfig.secretKey,
    },
    forcePathStyle: storageConfig.forcePathStyle,
    requestHandler: {
      requestTimeout: 300000, // 5 minutes timeout for S3 operations
      ...(s3HttpsAgent ? { httpsAgent: s3HttpsAgent } : {}),
    },
  };

  return new S3Client(publicConfig);
}
