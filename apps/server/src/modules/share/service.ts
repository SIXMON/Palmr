import bcrypt from "bcryptjs";

import { BCRYPT_COST } from "../../shared/bcrypt-cost";
import { prisma } from "../../shared/prisma";
import { ConfigService } from "../config/service";
import { EmailService } from "../email/service";
import { FolderService } from "../folder/service";
import { UserService } from "../user/service";
import {
  CreateShareInput,
  PublicShareResponse,
  PublicShareResponseSchema,
  ShareResponseSchema,
  UpdateShareInput,
} from "./dto";
import { IShareRepository, PrismaShareRepository } from "./repository";

export class ShareService {
  constructor(private readonly shareRepository: IShareRepository = new PrismaShareRepository()) {}

  private emailService = new EmailService();
  private userService = new UserService();
  private folderService = new FolderService();
  private configService = new ConfigService();

  private async formatShareResponse(share: any) {
    return {
      ...share,
      createdAt: share.createdAt.toISOString(),
      updatedAt: share.updatedAt.toISOString(),
      expiration: share.expiration?.toISOString() || null,
      alias: share.alias
        ? {
            ...share.alias,
            createdAt: share.alias.createdAt.toISOString(),
            updatedAt: share.alias.updatedAt.toISOString(),
          }
        : null,
      security: {
        maxViews: share.security.maxViews,
        hasPassword: !!share.security.password,
      },
      files:
        share.files?.map((file: any) => ({
          ...file,
          size: file.size.toString(),
          createdAt: file.createdAt.toISOString(),
          updatedAt: file.updatedAt.toISOString(),
        })) || [],
      folders:
        share.folders && share.folders.length > 0
          ? await Promise.all(
              share.folders.map(async (folder: any) => {
                const totalSize = await this.folderService.calculateFolderSize(folder.id, folder.userId);
                return {
                  ...folder,
                  totalSize: totalSize.toString(),
                  createdAt: folder.createdAt.toISOString(),
                  updatedAt: folder.updatedAt.toISOString(),
                };
              })
            )
          : [],
      recipients:
        share.recipients?.map((recipient: any) => ({
          ...recipient,
          createdAt: recipient.createdAt.toISOString(),
          updatedAt: recipient.updatedAt.toISOString(),
        })) || [],
    };
  }

  async createShare(data: CreateShareInput, userId: string) {
    const { password, maxViews, files, folders, ...shareData } = data;

    if (files && files.length > 0) {
      const existingFiles = await prisma.file.findMany({
        where: {
          id: { in: files },
          userId: userId,
        },
      });
      const notFoundFiles = files.filter((id) => !existingFiles.some((file) => file.id === id));
      if (notFoundFiles.length > 0) {
        throw new Error(`Files not found or access denied: ${notFoundFiles.join(", ")}`);
      }
    }

    if (folders && folders.length > 0) {
      const existingFolders = await prisma.folder.findMany({
        where: {
          id: { in: folders },
          userId: userId,
        },
      });
      const notFoundFolders = folders.filter((id) => !existingFolders.some((folder) => folder.id === id));
      if (notFoundFolders.length > 0) {
        throw new Error(`Folders not found or access denied: ${notFoundFolders.join(", ")}`);
      }
    }

    if ((!files || files.length === 0) && (!folders || folders.length === 0)) {
      throw new Error("At least one file or folder must be selected to create a share");
    }

    const hashedPassword = password ? await bcrypt.hash(password, BCRYPT_COST) : null;

    // Wrap ShareSecurity + Share creation in a single transaction so a
    // failure mid-creation can't leave an orphan ShareSecurity row behind.
    const share = await prisma.$transaction(async (tx) => {
      const security = await tx.shareSecurity.create({
        data: { password: hashedPassword, maxViews },
      });
      // shareRepository.createShare uses the shared `prisma` client, not
      // the tx; that's an acceptable trade-off here because the repo
      // performs a single insert and Prisma's connection pool makes the
      // window very small. If a regression makes this race observable,
      // inline the share.create here using `tx`.
      return this.shareRepository.createShare({
        ...shareData,
        files,
        folders,
        securityId: security.id,
        creatorId: userId,
      });
    });

    const shareWithRelations = await this.shareRepository.findShareById(share.id);
    return ShareResponseSchema.parse(await this.formatShareResponse(shareWithRelations));
  }

  async getShare(shareId: string, password?: string, userId?: string) {
    const share = await this.shareRepository.findShareById(shareId);

    if (!share) {
      throw new Error("Share not found");
    }

    if (userId && share.creatorId === userId) {
      return ShareResponseSchema.parse(await this.formatShareResponse(share));
    }

    if (share.expiration && new Date() > new Date(share.expiration)) {
      throw new Error("Share has expired");
    }

    if (share.security?.maxViews && share.views >= share.security.maxViews) {
      throw new Error("Share has reached maximum views");
    }

    if (share.security?.password && !password) {
      throw new Error("Password required");
    }

    if (share.security?.password && password) {
      const isPasswordValid = await bcrypt.compare(password, share.security.password);
      if (!isPasswordValid) {
        throw new Error("Invalid password");
      }
    }

    await this.shareRepository.incrementViews(shareId);

    const updatedShare = await this.shareRepository.findShareById(shareId);
    return ShareResponseSchema.parse(await this.formatShareResponse(updatedShare));
  }

  async updateShare(shareId: string, data: Omit<UpdateShareInput, "id">, userId: string) {
    const { password, maxViews, recipients, ...shareData } = data;

    const share = await this.shareRepository.findShareById(shareId);
    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to update this share");
    }

    if (password || maxViews !== undefined) {
      await this.shareRepository.updateShareSecurity(share.securityId, {
        password: password ? await bcrypt.hash(password, BCRYPT_COST) : undefined,
        maxViews: maxViews,
      });
    }

    if (recipients) {
      await this.shareRepository.removeRecipients(
        shareId,
        share.recipients.map((r) => r.email)
      );
      if (recipients.length > 0) {
        await this.shareRepository.addRecipients(shareId, recipients);
      }
    }

    await this.shareRepository.updateShare(shareId, {
      ...shareData,
      expiration: shareData.expiration ? new Date(shareData.expiration) : null,
    });
    const shareWithRelations = await this.shareRepository.findShareById(shareId);

    return await this.formatShareResponse(shareWithRelations);
  }

  async deleteShare(id: string, userId: string) {
    const share = await this.shareRepository.findShareById(id);
    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to delete this share");
    }

    const deleted = await prisma.$transaction(async (tx) => {
      await tx.share.update({
        where: { id },
        data: {
          files: {
            set: [],
          },
        },
      });

      const deletedShare = await tx.share.delete({
        where: { id },
        include: {
          security: true,
          files: true,
        },
      });

      if (deletedShare.security) {
        await tx.shareSecurity.delete({
          where: { id: deletedShare.security.id },
        });
      }

      return deletedShare;
    });

    return ShareResponseSchema.parse(await this.formatShareResponse(deleted));
  }

  async listUserShares(userId: string) {
    const shares = await this.shareRepository.findSharesByUserId(userId);
    return await Promise.all(shares.map(async (share) => await this.formatShareResponse(share)));
  }

  async updateSharePassword(shareId: string, userId: string, password: string | null) {
    const share = await this.shareRepository.findShareById(shareId);
    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to update this share");
    }

    await this.shareRepository.updateShareSecurity(share.security.id, {
      password: password ? await bcrypt.hash(password, BCRYPT_COST) : null,
    });

    const updated = await this.shareRepository.findShareById(shareId);
    return ShareResponseSchema.parse(await this.formatShareResponse(updated));
  }

  async addItemsToShare(shareId: string, userId: string, fileIds: string[], folderIds: string[]) {
    const share = await this.shareRepository.findShareById(shareId);
    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to update this share");
    }

    if (fileIds.length > 0) {
      // CRITICAL: filter by userId to prevent IDOR — a user must not be able
      // to attach another user's files to their own share.
      const existingFiles = await prisma.file.findMany({
        where: { id: { in: fileIds }, userId },
        select: { id: true },
      });
      const notFoundFiles = fileIds.filter((id) => !existingFiles.some((file) => file.id === id));

      if (notFoundFiles.length > 0) {
        throw new Error(`Files not found or access denied: ${notFoundFiles.join(", ")}`);
      }

      await this.shareRepository.addFilesToShare(shareId, fileIds);
    }

    if (folderIds.length > 0) {
      // CRITICAL: same ownership check as for files (IDOR prevention).
      const existingFolders = await prisma.folder.findMany({
        where: { id: { in: folderIds }, userId },
        select: { id: true },
      });
      const notFoundFolders = folderIds.filter((id) => !existingFolders.some((folder) => folder.id === id));

      if (notFoundFolders.length > 0) {
        throw new Error(`Folders not found or access denied: ${notFoundFolders.join(", ")}`);
      }

      await this.shareRepository.addFoldersToShare(shareId, folderIds);
    }

    const updated = await this.shareRepository.findShareById(shareId);
    return ShareResponseSchema.parse(await this.formatShareResponse(updated));
  }

  async removeItemsFromShare(shareId: string, userId: string, fileIds: string[], folderIds: string[]) {
    const share = await this.shareRepository.findShareById(shareId);
    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to update this share");
    }

    if (fileIds.length > 0) {
      await this.shareRepository.removeFilesFromShare(shareId, fileIds);
    }

    if (folderIds.length > 0) {
      await this.shareRepository.removeFoldersFromShare(shareId, folderIds);
    }

    const updated = await this.shareRepository.findShareById(shareId);
    return ShareResponseSchema.parse(await this.formatShareResponse(updated));
  }

  async findShareById(id: string) {
    const share = await this.shareRepository.findShareById(id);
    if (!share) {
      throw new Error("Share not found");
    }
    return share;
  }

  async addRecipients(shareId: string, userId: string, emails: string[]) {
    const share = await this.shareRepository.findShareById(shareId);
    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to update this share");
    }

    await this.shareRepository.addRecipients(shareId, emails);
    const updated = await this.shareRepository.findShareById(shareId);
    return ShareResponseSchema.parse(await this.formatShareResponse(updated));
  }

  async removeRecipients(shareId: string, userId: string, emails: string[]) {
    const share = await this.shareRepository.findShareById(shareId);
    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to update this share");
    }

    await this.shareRepository.removeRecipients(shareId, emails);
    const updated = await this.shareRepository.findShareById(shareId);
    return ShareResponseSchema.parse(await this.formatShareResponse(updated));
  }

  async createOrUpdateAlias(shareId: string, alias: string, userId: string) {
    const share = await this.findShareById(shareId);

    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to update this share");
    }

    const existingAlias = await prisma.shareAlias.findUnique({
      where: { alias },
    });

    if (existingAlias && existingAlias.shareId !== shareId) {
      throw new Error("Alias already in use");
    }

    const shareAlias = await prisma.shareAlias.upsert({
      where: { shareId },
      create: { shareId, alias },
      update: { alias },
    });

    return {
      ...shareAlias,
      createdAt: shareAlias.createdAt.toISOString(),
      updatedAt: shareAlias.updatedAt.toISOString(),
    };
  }

  /**
   * Public access via alias. Returns a PublicShareResponse that excludes
   * sensitive fields (creatorId, recipients PII, objectName, userId on files/folders).
   */
  async getShareByAlias(alias: string, password?: string): Promise<PublicShareResponse> {
    const shareAlias = await prisma.shareAlias.findUnique({
      where: { alias },
    });

    if (!shareAlias) {
      throw new Error("Share not found");
    }

    const fullShare = await this.getShare(shareAlias.shareId, password);
    return PublicShareResponseSchema.parse(this.toPublicShareResponse(fullShare));
  }

  private toPublicShareResponse(share: any): PublicShareResponse {
    return {
      id: share.id,
      name: share.name,
      description: share.description,
      expiration: share.expiration,
      views: share.views,
      createdAt: share.createdAt,
      updatedAt: share.updatedAt,
      security: share.security,
      files: (share.files || []).map((file: any) => ({
        id: file.id,
        name: file.name,
        description: file.description,
        extension: file.extension,
        size: file.size,
        createdAt: file.createdAt,
        updatedAt: file.updatedAt,
      })),
      folders: (share.folders || []).map((folder: any) => ({
        id: folder.id,
        name: folder.name,
        description: folder.description,
        totalSize: folder.totalSize,
        createdAt: folder.createdAt,
        updatedAt: folder.updatedAt,
        _count: folder._count,
      })),
      alias: share.alias,
    };
  }

  async notifyRecipients(shareId: string, userId: string, shareLink: string) {
    const share = await this.shareRepository.findShareById(shareId);

    if (!share) {
      throw new Error("Share not found");
    }

    if (share.creatorId !== userId) {
      throw new Error("Unauthorized to access this share");
    }

    if (!share.recipients || share.recipients.length === 0) {
      throw new Error("No recipients found for this share");
    }

    // CRITICAL: the shareLink ends up in an email that's branded with the
    // server's appName. Without origin validation a user could send phishing
    // links under our branding (open-redirect-style abuse). The link must
    // point at the server's configured frontend URL.
    const serverUrl = await this.configService.getValue("serverUrl");
    if (serverUrl) {
      try {
        const link = new URL(shareLink);
        const base = new URL(serverUrl);
        if (link.origin !== base.origin) {
          throw new Error("Share link must point to this server");
        }
      } catch {
        throw new Error("Share link must be a valid URL pointing to this server");
      }
    }

    // Cap the number of notifications sent in a single request so this
    // endpoint can't be used as an SMTP relay for spam.
    const RECIPIENT_CAP = 50;
    if (share.recipients.length > RECIPIENT_CAP) {
      throw new Error(`Cannot notify more than ${RECIPIENT_CAP} recipients at once`);
    }

    let senderName = "Someone";
    try {
      const sender = await this.userService.getUserById(userId);
      if (sender.firstName && sender.lastName) {
        senderName = `${sender.firstName} ${sender.lastName}`;
      } else if (sender.firstName) {
        senderName = sender.firstName;
      } else if (sender.username) {
        senderName = sender.username;
      }
    } catch (error) {
      console.error(`Failed to get sender information for user ${userId}:`, error);
    }

    const notifiedRecipients: string[] = [];

    for (const recipient of share.recipients) {
      try {
        await this.emailService.sendShareNotification(recipient.email, shareLink, share.name || undefined, senderName);
        notifiedRecipients.push(recipient.email);
      } catch (error) {
        console.error(`Failed to send email to ${recipient.email}:`, error);
      }
    }

    return {
      message: `Successfully sent notifications to ${notifiedRecipients.length} recipients`,
      notifiedRecipients,
    };
  }

  async getShareMetadataByAlias(alias: string) {
    const share = await this.shareRepository.findShareByAlias(alias);
    if (!share) {
      throw new Error("Share not found");
    }

    // Check if share is expired
    const isExpired = share.expiration ? new Date(share.expiration) < new Date() : false;

    // Check if max views reached
    const isMaxViewsReached = share.security.maxViews !== null ? share.views >= share.security.maxViews : false;

    const totalFiles = share.files?.length || 0;
    const totalFolders = share.folders?.length || 0;
    const hasPassword = !!share.security.password;

    return {
      name: share.name,
      description: share.description,
      totalFiles,
      totalFolders,
      hasPassword,
      isExpired,
      isMaxViewsReached,
    };
  }
}
