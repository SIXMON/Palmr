"use client";

import { useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { useAuth } from "@/contexts/auth-context";
import { getCurrentUser } from "@/http/endpoints";

const ERROR_MESSAGES: Record<string, string> = {
  oauth_error: "OAuth authentication failed",
  missing_parameters: "Missing authentication parameters",
  registration_disabled: "Registration is disabled for this provider",
  provider_disabled: "This authentication provider is disabled",
  state_expired: "Authentication session expired",
  account_inactive: "Your account is inactive",
};

export default function AuthCallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { setUser, setIsAuthenticated, setIsAdmin } = useAuth();
  const t = useTranslations();

  // Guard against running the finalise effect twice in dev (React 18
  // strict mode mounts components twice) — the second run would race
  // the first and trigger duplicate toasts / a stale router.push.
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    const error = searchParams.get("error");
    if (error) {
      toast.error(ERROR_MESSAGES[error] ?? "Authentication failed");
      router.replace("/login");
      return;
    }

    // Legacy fallback: some deployments hand the JWT back via the URL
    // (`?token=…`) instead of a cookie. Set it as a cookie so the
    // subsequent /auth/me call picks it up.
    const token = searchParams.get("token");
    if (token) {
      document.cookie = `token=${token}; path=/; max-age=${7 * 24 * 60 * 60}; samesite=lax`;
    }

    // In the default (cookie) flow, the backend has already set the
    // session cookie on the Set-Cookie response of the OAuth callback.
    // We just need to confirm the session is valid and push the user
    // to /dashboard. AuthProvider's own mount-time fetch races us, so
    // we update its state directly here on success to avoid a flash
    // of unauthenticated state on /dashboard.
    (async () => {
      try {
        const response = await getCurrentUser();
        if (!response?.data?.user) {
          throw new Error("no user");
        }
        const { isAdmin, ...userData } = response.data.user;
        setUser(userData);
        setIsAdmin(isAdmin);
        setIsAuthenticated(true);
        toast.success(t("auth.successfullyAuthenticated"));
        router.replace("/dashboard");
      } catch (err) {
        console.error("auth callback fetch user:", err);
        toast.error(t("auth.authenticationFailed"));
        router.replace("/login");
      }
    })();
  }, [router, searchParams, setUser, setIsAuthenticated, setIsAdmin, t]);

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
        <p className="text-muted-foreground">Processing authentication...</p>
      </div>
    </div>
  );
}
