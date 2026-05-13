import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

// Same pattern as (shares)/s/[alias]/layout.tsx — static fallback at
// build time, dynamic OG tags served by the Go backend at /og/r/{alias}
// for crawler User-Agents (see apps/web/nginx.conf).
export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations();
  return {
    title: t("reverseShares.upload.metadata.title"),
    description: t("reverseShares.upload.metadata.description"),
    openGraph: {
      title: t("reverseShares.upload.metadata.title"),
      description: t("reverseShares.upload.metadata.description"),
      type: "website",
    },
    twitter: {
      card: "summary_large_image",
      title: t("reverseShares.upload.metadata.title"),
      description: t("reverseShares.upload.metadata.description"),
    },
  };
}

// See sibling /s/[alias]/layout.tsx for the rationale — single placeholder
// HTML, runtime alias resolution from window.location.
export function generateStaticParams() {
  return [{ alias: "_" }];
}

export default function ReverseShareLayout({ children }: { children: React.ReactNode }) {
  return children;
}
