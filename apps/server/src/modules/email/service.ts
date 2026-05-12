import nodemailer from "nodemailer";

import { ConfigService } from "../config/service";

/**
 * Escape a string for safe inclusion in HTML text/attribute context.
 * Mail bodies are user-controlled (share names, sender names, file names),
 * and a few mail clients still render JS — but more importantly, unescaped
 * input lets an attacker forge phishing links/markup inside our branding.
 */
function escapeHtml(value: string | null | undefined): string {
  if (value == null) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Strip CRLF (header injection) and HTML from email subjects.
 */
function sanitizeSubject(value: string | null | undefined): string {
  if (value == null) return "";
  return String(value)
    .replace(/[\r\n]+/g, " ")
    .replace(/[<>]/g, "")
    .slice(0, 200);
}

interface SmtpConfig {
  smtpEnabled: string;
  smtpHost: string;
  smtpPort: string;
  smtpUser: string;
  smtpPass: string;
  smtpSecure?: string;
  smtpNoAuth?: string;
  smtpTrustSelfSigned?: string;
}

export class EmailService {
  private configService = new ConfigService();

  private async createTransporter() {
    const smtpEnabled = await this.configService.getValue("smtpEnabled");
    if (smtpEnabled !== "true") {
      return null;
    }

    const port = Number(await this.configService.getValue("smtpPort"));
    const smtpSecure = (await this.configService.getValue("smtpSecure")) || "auto";
    const smtpNoAuth = await this.configService.getValue("smtpNoAuth");
    const smtpTrustSelfSigned = await this.configService.getValue("smtpTrustSelfSigned");

    let secure = false;
    let requireTLS = false;

    if (smtpSecure === "ssl") {
      secure = true;
    } else if (smtpSecure === "tls") {
      requireTLS = true;
    } else if (smtpSecure === "none") {
      secure = false;
      requireTLS = false;
    } else if (smtpSecure === "auto") {
      if (port === 465) {
        secure = true;
      } else if (port === 587 || port === 25) {
        requireTLS = true;
      }
    }

    const transportConfig: any = {
      host: await this.configService.getValue("smtpHost"),
      port: port,
      secure: secure,
      requireTLS: requireTLS,
    };

    if (smtpSecure !== "none") {
      transportConfig.tls = {
        rejectUnauthorized: smtpTrustSelfSigned === "true" ? false : true,
      };
    }

    if (smtpNoAuth !== "true") {
      transportConfig.auth = {
        user: await this.configService.getValue("smtpUser"),
        pass: await this.configService.getValue("smtpPass"),
      };
    }

    return nodemailer.createTransport(transportConfig);
  }

  async testConnection(config?: SmtpConfig) {
    let smtpConfig: SmtpConfig;

    if (config) {
      smtpConfig = config;
    } else {
      smtpConfig = {
        smtpEnabled: await this.configService.getValue("smtpEnabled"),
        smtpHost: await this.configService.getValue("smtpHost"),
        smtpPort: await this.configService.getValue("smtpPort"),
        smtpUser: await this.configService.getValue("smtpUser"),
        smtpPass: await this.configService.getValue("smtpPass"),
        smtpSecure: (await this.configService.getValue("smtpSecure")) || "auto",
        smtpNoAuth: await this.configService.getValue("smtpNoAuth"),
        smtpTrustSelfSigned: await this.configService.getValue("smtpTrustSelfSigned"),
      };
    }

    if (smtpConfig.smtpEnabled !== "true") {
      throw new Error("SMTP is not enabled");
    }

    const port = Number(smtpConfig.smtpPort);
    const smtpSecure = smtpConfig.smtpSecure || "auto";
    const smtpNoAuth = smtpConfig.smtpNoAuth;

    let secure = false;
    let requireTLS = false;

    if (smtpSecure === "ssl") {
      secure = true;
    } else if (smtpSecure === "tls") {
      requireTLS = true;
    } else if (smtpSecure === "none") {
      secure = false;
      requireTLS = false;
    } else if (smtpSecure === "auto") {
      if (port === 465) {
        secure = true;
      } else if (port === 587 || port === 25) {
        requireTLS = true;
      }
    }

    const transportConfig: any = {
      host: smtpConfig.smtpHost,
      port: port,
      secure: secure,
      requireTLS: requireTLS,
    };

    if (smtpSecure !== "none") {
      transportConfig.tls = {
        rejectUnauthorized: smtpConfig.smtpTrustSelfSigned === "true" ? false : true,
      };
    }

    if (smtpNoAuth !== "true") {
      transportConfig.auth = {
        user: smtpConfig.smtpUser,
        pass: smtpConfig.smtpPass,
      };
    }

    const transporter = nodemailer.createTransport(transportConfig);

    try {
      await transporter.verify();
      return { success: true, message: "SMTP connection successful" };
    } catch (error: any) {
      throw new Error(`SMTP connection failed: ${error.message}`);
    }
  }

  async sendPasswordResetEmail(to: string, resetUrl: string, expirationSeconds: number) {
    const transporter = await this.createTransporter();
    if (!transporter) {
      throw new Error("SMTP is not enabled");
    }

    const fromName = await this.configService.getValue("smtpFromName");
    const fromEmail = await this.configService.getValue("smtpFromEmail");
    const appName = await this.configService.getValue("appName");

    const safeAppName = escapeHtml(appName);
    // resetUrl is built server-side; we only escape it for HTML-safe rendering.
    const safeResetUrl = escapeHtml(resetUrl);
    const minutes = Math.max(1, Math.round(expirationSeconds / 60));

    await transporter.sendMail({
      from: `"${sanitizeSubject(fromName)}" <${fromEmail}>`,
      to,
      subject: sanitizeSubject(`${appName} - Password Reset Request`),
      html: `
        <h1>${safeAppName} - Password Reset Request</h1>
        <p>Click the link below to reset your password:</p>
        <a href="${safeResetUrl}">Reset Password</a>
        <p>This link will expire in ${minutes} minute${minutes === 1 ? "" : "s"}.</p>
      `,
    });
  }

  async sendShareNotification(to: string, shareLink: string, shareName?: string, senderName?: string) {
    const transporter = await this.createTransporter();
    if (!transporter) {
      throw new Error("SMTP is not enabled");
    }

    const fromName = await this.configService.getValue("smtpFromName");
    const fromEmail = await this.configService.getValue("smtpFromEmail");
    const appName = await this.configService.getValue("appName");

    const shareTitle = shareName || "Files";
    const sender = senderName || "Someone";
    const safeAppName = escapeHtml(appName);
    const safeShareTitle = escapeHtml(shareTitle);
    const safeSender = escapeHtml(sender);
    const safeShareLink = escapeHtml(shareLink);

    await transporter.sendMail({
      from: `"${sanitizeSubject(fromName)}" <${fromEmail}>`,
      to,
      subject: sanitizeSubject(`${appName} - ${shareTitle} shared with you`),
      html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${safeAppName} - Shared Files</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5; color: #333333;">
          <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1); overflow: hidden; margin-top: 40px; margin-bottom: 40px;">
            <div style="background-color: #22B14C; padding: 30px 20px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600; letter-spacing: -0.5px;">${safeAppName}</h1>
              <p style="margin: 2px 0 0 0; color: #ffffff; font-size: 16px; opacity: 0.9;">Shared Files</p>
            </div>
            <div style="padding: 40px 30px;">
              <div style="text-align: center; margin-bottom: 32px;">
                <h2 style="margin: 0 0 12px 0; color: #1f2937; font-size: 24px; font-weight: 600;">Files Shared With You</h2>
                <p style="margin: 0; color: #6b7280; font-size: 16px; line-height: 1.6;">
                  <strong style="color: #374151;">${safeSender}</strong> has shared <strong style="color: #374151;">"${safeShareTitle}"</strong> with you.
                </p>
              </div>
              <div style="text-align: center; margin: 32px 0;">
                <a href="${safeShareLink}" style="display: inline-block; background-color: #22B14C; color: #ffffff; text-decoration: none; padding: 12px 24px; font-weight: 600; font-size: 16px; border: 2px solid #22B14C; border-radius: 8px;">
                  Access Shared Files
                </a>
              </div>
              <div style="background-color: #f9fafb; border-left: 4px solid #22B14C; padding: 16px 20px; margin-top: 32px;">
                <p style="margin: 0; color: #4b5563; font-size: 14px; line-height: 1.5;">
                  <strong>Important:</strong> This share may have an expiration date or view limit. Access it as soon as possible to ensure availability.
                </p>
              </div>
            </div>
            <div style="background-color: #f9fafb; padding: 24px 30px; text-align: center; border-top: 1px solid #e5e7eb;">
              <p style="margin: 0; color: #6b7280; font-size: 14px;">
                This email was sent by <strong>${safeAppName}</strong>
              </p>
              <p style="margin: 8px 0 0 0; color: #9ca3af; font-size: 12px;">
                If you didn't expect this email, you can safely ignore it.
              </p>
            </div>
          </div>
        </body>
        </html>
      `,
    });
  }

  async sendReverseShareBatchFileNotification(
    recipientEmail: string,
    reverseShareName: string,
    fileCount: number,
    fileList: string,
    uploaderName: string
  ) {
    const transporter = await this.createTransporter();
    if (!transporter) {
      throw new Error("SMTP is not enabled");
    }

    const fromName = await this.configService.getValue("smtpFromName");
    const fromEmail = await this.configService.getValue("smtpFromEmail");
    const appName = await this.configService.getValue("appName");

    const safeAppName = escapeHtml(appName);
    const safeReverseShareName = escapeHtml(reverseShareName);
    const safeUploaderName = escapeHtml(uploaderName);
    const fileItems = fileList
      .split(", ")
      .map((file) => `<li style="margin: 4px 0;">${escapeHtml(file)}</li>`)
      .join("");

    await transporter.sendMail({
      from: `"${sanitizeSubject(fromName)}" <${fromEmail}>`,
      to: recipientEmail,
      subject: sanitizeSubject(
        `${appName} - ${fileCount} file${fileCount > 1 ? "s" : ""} uploaded to "${reverseShareName}"`
      ),
      html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${safeAppName} - File Upload Notification</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5; color: #333333;">
          <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1); overflow: hidden; margin-top: 40px; margin-bottom: 40px;">
            <div style="background-color: #22B14C; padding: 30px 20px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600; letter-spacing: -0.5px;">${safeAppName}</h1>
              <p style="margin: 2px 0 0 0; color: #ffffff; font-size: 16px; opacity: 0.9;">File Upload Notification</p>
            </div>
            <div style="padding: 40px 30px;">
              <div style="text-align: center; margin-bottom: 32px;">
                <h2 style="margin: 0 0 12px 0; color: #1f2937; font-size: 24px; font-weight: 600;">New File Uploaded</h2>
                <p style="margin: 0; color: #6b7280; font-size: 16px; line-height: 1.6;">
                  <strong style="color: #374151;">${safeUploaderName}</strong> has uploaded <strong style="color: #374151;">${fileCount} file${fileCount > 1 ? "s" : ""}</strong> to your reverse share <strong style="color: #374151;">"${safeReverseShareName}"</strong>.
                </p>
              </div>
              <div style="background-color: #f9fafb; border-radius: 8px; padding: 16px; margin: 32px 0; border-left: 4px solid #22B14C;">
                <p style="margin: 0 0 8px 0; color: #374151; font-size: 14px;"><strong>Files (${fileCount}):</strong></p>
                <ul style="margin: 0; padding-left: 20px; color: #6b7280; font-size: 14px; line-height: 1.5;">
                  ${fileItems}
                </ul>
              </div>
              <div style="text-align: center; margin-top: 32px;">
                <p style="margin: 0; color: #9ca3af; font-size: 12px;">
                  You can now access and manage these files through your dashboard.
                </p>
              </div>
            </div>
            <div style="background-color: #f9fafb; padding: 24px 30px; text-align: center; border-top: 1px solid #e5e7eb;">
              <p style="margin: 0; color: #6b7280; font-size: 14px;">
                This email was sent by <strong>${safeAppName}</strong>
              </p>
              <p style="margin: 8px 0 0 0; color: #9ca3af; font-size: 12px;">
                If you didn't expect this email, you can safely ignore it.
              </p>
            </div>
          </div>
        </body>
        </html>
      `,
    });
  }
}
