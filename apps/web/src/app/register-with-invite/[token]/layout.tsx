import { Metadata } from "next";
import { getTranslations } from "next-intl/server";

interface LayoutProps {
  children: React.ReactNode;
}

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations();

  return {
    title: `${t("registerWithInvite.pageTitle")} `,
  };
}

// Static export needs one pre-rendered HTML per dynamic route. We emit a
// single `_` placeholder and nginx rewrites every real token URL to the
// same scaffold; the client React app reads the token from
// window.location and validates it via the backend at runtime.
export function generateStaticParams() {
  return [{ token: "_" }];
}

export default function RegisterWithInviteLayout({ children }: LayoutProps) {
  return <>{children}</>;
}
