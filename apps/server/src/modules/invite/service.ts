import { randomBytes } from "crypto";
import bcrypt from "bcryptjs";

import { prisma } from "../../shared/prisma";

export class InviteService {
  async generateInviteToken(adminUserId: string): Promise<{ token: string; expiresAt: Date }> {
    const token = randomBytes(32).toString("hex");
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 15);

    await prisma.inviteToken.create({
      data: {
        token,
        expiresAt,
        createdBy: adminUserId,
      },
    });

    return { token, expiresAt };
  }

  async validateInviteToken(token: string): Promise<{ valid: boolean; used?: boolean; expired?: boolean }> {
    const inviteToken = await prisma.inviteToken.findUnique({
      where: { token },
    });

    if (!inviteToken) {
      return { valid: false };
    }

    if (inviteToken.usedAt) {
      return { valid: false, used: true };
    }

    if (new Date() > inviteToken.expiresAt) {
      return { valid: false, expired: true };
    }

    return { valid: true };
  }

  async registerWithInvite(data: {
    token: string;
    firstName: string;
    lastName: string;
    username: string;
    email: string;
    password: string;
  }): Promise<{ id: string; username: string; email: string }> {
    // Existence check before bcrypt to fail fast on obvious dupes.
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username: data.username }, { email: data.email }],
      },
    });

    if (existingUser) {
      if (existingUser.username === data.username) {
        throw new Error("Username already exists");
      }
      if (existingUser.email === data.email) {
        throw new Error("Email already exists");
      }
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);

    // CRITICAL: claim the invite token atomically. updateMany returns
    // count > 0 only if the token is unused and not expired, so two
    // concurrent registrations cannot both succeed with the same token.
    const result = await prisma.$transaction(async (tx) => {
      const claim = await tx.inviteToken.updateMany({
        where: {
          token: data.token,
          usedAt: null,
          expiresAt: { gt: new Date() },
        },
        data: { usedAt: new Date() },
      });

      if (claim.count !== 1) {
        // Re-read to give a precise error message
        const inviteToken = await tx.inviteToken.findUnique({ where: { token: data.token } });
        if (!inviteToken) throw new Error("Invalid invite link");
        if (inviteToken.usedAt) throw new Error("This invite link has already been used");
        if (new Date() > inviteToken.expiresAt) throw new Error("This invite link has expired");
        throw new Error("Invalid invite link");
      }

      const user = await tx.user.create({
        data: {
          firstName: data.firstName,
          lastName: data.lastName,
          username: data.username,
          email: data.email,
          password: hashedPassword,
          isAdmin: false,
          isActive: true,
        },
        select: {
          id: true,
          username: true,
          email: true,
        },
      });

      return user;
    });

    return result;
  }
}
