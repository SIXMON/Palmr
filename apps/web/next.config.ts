import { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const nextConfig: NextConfig = {
  // Static export: every page is pre-rendered to HTML at build time and
  // served as a flat directory by nginx in the runtime container. All
  // user data still loads at runtime via XHR against the Go backend
  // (see nginx.conf for the /api proxy + /e/{id} proxy + /og/{s,r}/...
  // bot-UA split).
  output: "export",
  // trailingSlash keeps every route as a directory with index.html so
  // nginx's `try_files` patterns stay simple (`/login/` → `/login/index.html`).
  trailingSlash: true,
  // Static export can't run the Image Optimization API at runtime, so
  // images get served as-is. We don't use next/image transforms heavily
  // anyway — most images come from the backend already sized.
  images: {
    unoptimized: true,
    remotePatterns: [
      {
        protocol: "https",
        hostname: "**",
      },
      {
        protocol: "http",
        hostname: "**",
      },
    ],
  },
  serverExternalPackages: [],
};

const withNextIntl = createNextIntlPlugin();
export default withNextIntl(nextConfig);
