import { z } from "zod";

import { ConfigService } from "../config/service";

const configService = new ConfigService();

export const createPasswordSchema = async () => {
  const minLength = Number(await configService.getValue("passwordMinLength"));
  return z.string().min(minLength, `Password must be at least ${minLength} characters`).describe("User password");
};

export const LoginSchema = z.object({
  emailOrUsername: z.string().min(1, "Email or username is required").max(255).describe("User email or username"),
  // No min-length: a user whose stored password is shorter than the
  // currently-configured passwordMinLength (admin raised it after signup)
  // must still be able to authenticate. The signup flow enforces the policy.
  password: z.string().min(1, "Password is required").max(1024).describe("User password"),
});
export type LoginInput = z.infer<typeof LoginSchema>;

export const RequestPasswordResetSchema = z.object({
  email: z.string().email("Invalid email").describe("User email"),
});

export const BaseResetPasswordSchema = z.object({
  token: z.string().min(1, "Token is required").describe("Reset password token"),
});

export type BaseResetPasswordInput = z.infer<typeof BaseResetPasswordSchema>;

export const createResetPasswordSchema = async () => {
  const minLength = Number(await configService.getValue("passwordMinLength"));
  return BaseResetPasswordSchema.extend({
    password: z.string().min(minLength, `Password must be at least ${minLength} characters`).describe("User password"),
  });
};

export type ResetPasswordInput = BaseResetPasswordInput & {
  password: string;
};

export const CompleteTwoFactorLoginSchema = z.object({
  pre2faToken: z.string().min(1, "Pre-2FA token is required").describe("Server-issued token from /auth/login"),
  // Accept either a 6-digit TOTP or a backup code in XXXX-XXXX hex format.
  // Restricting the format up-front rejects obvious junk before the throttle
  // counter gets bumped on a malformed input.
  token: z
    .string()
    .regex(/^(\d{6}|[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4})$/, "Invalid 2FA token format")
    .describe("6-digit TOTP code or XXXX-XXXX hex backup code"),
  rememberDevice: z.boolean().optional().default(false).describe("Remember this device for 30 days"),
});

export type CompleteTwoFactorLoginInput = z.infer<typeof CompleteTwoFactorLoginSchema>;
