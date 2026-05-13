import { Metadata } from "next";
import { getTranslations } from "next-intl/server";

interface LayoutProps {
  children: React.ReactNode;
  params: Promise<{ alias: string }>;
}

// Static export forces this to run once at build time for the placeholder
// alias, so we emit generic fallback OG tags here. Bots that need the
// real share metadata are routed by nginx to /og/s/{alias} on the Go
// backend, which renders a thin HTML page with the dynamic tags.
export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations();
  return {
    title: t("share.pageTitle"),
    description: t("share.metadata.defaultDescription"),
    openGraph: {
      title: t("share.pageTitle"),
      description: t("share.metadata.defaultDescription"),
      type: "website",
    },
    twitter: {
      card: "summary_large_image",
      title: t("share.pageTitle"),
      description: t("share.metadata.defaultDescription"),
    },
  };
}

// Static export requires every dynamic route to declare which params to
// pre-render. We emit a single placeholder so Next.js generates exactly
// one HTML scaffold for /s/[alias]; nginx rewrites all real alias URLs
// (/s/anything-else) to that same scaffold and the client React app
// reads window.location.pathname via useParams() to load the right
// share at runtime.
export function generateStaticParams() {
  return [{ alias: "_" }];
}

export default function DashboardLayout({ children }: LayoutProps) {
  return <>{children}</>;
}
