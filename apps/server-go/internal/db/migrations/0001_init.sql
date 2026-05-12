-- Initial schema, captured from a working Prisma migration.
-- Every CREATE uses IF NOT EXISTS so this migration is safe to run on a
-- database bootstrapped by the legacy Node backend or by the first
-- revision of the Go backend.

-- +goose Up

CREATE TABLE IF NOT EXISTS "users" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT,
    "image" TEXT,
    "isAdmin" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorSecret" TEXT,
    "twoFactorBackupCodes" TEXT,
    "twoFactorVerified" BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS "files" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "extension" TEXT NOT NULL,
    "size" BIGINT NOT NULL,
    "objectName" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "folderId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "files_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "files_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "folders" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "shares" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT,
    "views" INTEGER NOT NULL DEFAULT 0,
    "expiration" DATETIME,
    "description" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "creatorId" TEXT NOT NULL,
    "securityId" TEXT NOT NULL,
    CONSTRAINT "shares_creatorId_fkey" FOREIGN KEY ("creatorId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "shares_securityId_fkey" FOREIGN KEY ("securityId") REFERENCES "share_security" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "share_security" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "password" TEXT,
    "maxViews" INTEGER,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS "share_recipients" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "shareId" TEXT NOT NULL,
    CONSTRAINT "share_recipients_shareId_fkey" FOREIGN KEY ("shareId") REFERENCES "shares" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "app_configs" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "group" TEXT NOT NULL,
    "isSystem" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS "login_attempts" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 1,
    "lastAttempt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "login_attempts_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "password_resets" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "password_resets_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "share_aliases" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "alias" TEXT NOT NULL,
    "shareId" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "share_aliases_shareId_fkey" FOREIGN KEY ("shareId") REFERENCES "shares" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "auth_providers" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "icon" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "issuerUrl" TEXT,
    "clientId" TEXT,
    "clientSecret" TEXT,
    "redirectUri" TEXT,
    "scope" TEXT DEFAULT 'openid profile email',
    "authorizationEndpoint" TEXT,
    "tokenEndpoint" TEXT,
    "userInfoEndpoint" TEXT,
    "metadata" TEXT,
    "autoRegister" BOOLEAN NOT NULL DEFAULT true,
    "adminEmailDomains" TEXT,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS "user_auth_providers" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "provider" TEXT,
    "externalId" TEXT NOT NULL,
    "metadata" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "user_auth_providers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "user_auth_providers_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "auth_providers" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "reverse_shares" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT,
    "description" TEXT,
    "expiration" DATETIME,
    "maxFiles" INTEGER,
    "maxFileSize" BIGINT,
    "allowedFileTypes" TEXT,
    "password" TEXT,
    "pageLayout" TEXT NOT NULL DEFAULT 'DEFAULT',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "nameFieldRequired" TEXT NOT NULL DEFAULT 'OPTIONAL',
    "emailFieldRequired" TEXT NOT NULL DEFAULT 'OPTIONAL',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "creatorId" TEXT NOT NULL,
    CONSTRAINT "reverse_shares_creatorId_fkey" FOREIGN KEY ("creatorId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "reverse_share_files" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "extension" TEXT NOT NULL,
    "size" BIGINT NOT NULL,
    "objectName" TEXT NOT NULL,
    "uploaderEmail" TEXT,
    "uploaderName" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "reverseShareId" TEXT NOT NULL,
    CONSTRAINT "reverse_share_files_reverseShareId_fkey" FOREIGN KEY ("reverseShareId") REFERENCES "reverse_shares" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "reverse_share_aliases" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "alias" TEXT NOT NULL,
    "reverseShareId" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "reverse_share_aliases_reverseShareId_fkey" FOREIGN KEY ("reverseShareId") REFERENCES "reverse_shares" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "trusted_devices" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "deviceHash" TEXT NOT NULL,
    "deviceName" TEXT,
    "userAgent" TEXT,
    "ipAddress" TEXT,
    "lastUsedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "trusted_devices_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "folders" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "objectName" TEXT NOT NULL,
    "parentId" TEXT,
    "userId" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "folders_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "folders" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "folders_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "invite_tokens" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "token" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL,
    "usedAt" DATETIME,
    "createdBy" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "invite_tokens_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "_ShareFiles" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL,
    CONSTRAINT "_ShareFiles_A_fkey" FOREIGN KEY ("A") REFERENCES "files" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "_ShareFiles_B_fkey" FOREIGN KEY ("B") REFERENCES "shares" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS "_ShareFolders" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL,
    CONSTRAINT "_ShareFolders_A_fkey" FOREIGN KEY ("A") REFERENCES "folders" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "_ShareFolders_B_fkey" FOREIGN KEY ("B") REFERENCES "shares" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS "users_username_key" ON "users"("username");
CREATE UNIQUE INDEX IF NOT EXISTS "users_email_key" ON "users"("email");
CREATE INDEX IF NOT EXISTS "files_folderId_idx" ON "files"("folderId");
CREATE UNIQUE INDEX IF NOT EXISTS "shares_securityId_key" ON "shares"("securityId");
CREATE UNIQUE INDEX IF NOT EXISTS "app_configs_key_key" ON "app_configs"("key");
CREATE UNIQUE INDEX IF NOT EXISTS "login_attempts_userId_key" ON "login_attempts"("userId");
CREATE UNIQUE INDEX IF NOT EXISTS "password_resets_token_key" ON "password_resets"("token");
CREATE UNIQUE INDEX IF NOT EXISTS "share_aliases_alias_key" ON "share_aliases"("alias");
CREATE UNIQUE INDEX IF NOT EXISTS "share_aliases_shareId_key" ON "share_aliases"("shareId");
CREATE UNIQUE INDEX IF NOT EXISTS "auth_providers_name_key" ON "auth_providers"("name");
CREATE UNIQUE INDEX IF NOT EXISTS "user_auth_providers_userId_providerId_key" ON "user_auth_providers"("userId", "providerId");
CREATE UNIQUE INDEX IF NOT EXISTS "user_auth_providers_providerId_externalId_key" ON "user_auth_providers"("providerId", "externalId");
CREATE UNIQUE INDEX IF NOT EXISTS "reverse_share_aliases_alias_key" ON "reverse_share_aliases"("alias");
CREATE UNIQUE INDEX IF NOT EXISTS "reverse_share_aliases_reverseShareId_key" ON "reverse_share_aliases"("reverseShareId");
CREATE UNIQUE INDEX IF NOT EXISTS "trusted_devices_userId_deviceHash_key" ON "trusted_devices"("userId", "deviceHash");
CREATE INDEX IF NOT EXISTS "folders_userId_idx" ON "folders"("userId");
CREATE INDEX IF NOT EXISTS "folders_parentId_idx" ON "folders"("parentId");
CREATE UNIQUE INDEX IF NOT EXISTS "invite_tokens_token_key" ON "invite_tokens"("token");
CREATE INDEX IF NOT EXISTS "invite_tokens_createdBy_idx" ON "invite_tokens"("createdBy");
CREATE UNIQUE INDEX IF NOT EXISTS "_ShareFiles_AB_unique" ON "_ShareFiles"("A", "B");
CREATE INDEX IF NOT EXISTS "_ShareFiles_B_index" ON "_ShareFiles"("B");
CREATE UNIQUE INDEX IF NOT EXISTS "_ShareFolders_AB_unique" ON "_ShareFolders"("A", "B");
CREATE INDEX IF NOT EXISTS "_ShareFolders_B_index" ON "_ShareFolders"("B");

-- +goose Down
-- Initial migration; nothing to undo.
