import { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const nextConfig: NextConfig = {
  // Static export: every page is pre-rendered to HTML at build time and
  // served as a flat directory by nginx in the runtime container. All
  // user data still loads at runtime via XHR against the Go backend
  // (see nginx.conf for the /api proxy + /e/{id} proxy + /og/{s,r}/...
  // bot-UA split).
  output: "export",
  // trailingSlash:false → Next.js generates `out/login.html` rather
  // than `out/login/index.html`. nginx serves the .html file directly
  // via `try_files $uri $uri.html …`, so the user sees `/login` in
  // their URL bar with no 301 round-trip. Switching to true would
  // make every first-visit URL emit a redirect to append the slash —
  // unnecessary noise, especially behind a TLS proxy where nginx
  // would have to know the public scheme/port to build the redirect
  // correctly.
  trailingSlash: false,
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
