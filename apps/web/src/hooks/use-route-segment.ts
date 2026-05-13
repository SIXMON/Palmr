"use client";

import { useState } from "react";

function extractSegment(pathname: string, prefix: string): string {
  if (!pathname.startsWith(prefix)) return "";
  const rest = pathname.slice(prefix.length);
  const head = rest.split("/")[0] ?? "";
  try {
    return decodeURIComponent(head);
  } catch {
    // Malformed URI — return as-is rather than throwing into React.
    return head;
  }
}

/**
 * Read a dynamic route segment from the current URL.
 *
 * Why this exists: under `output: "export"` Next.js pre-renders every
 * dynamic route against the params returned by `generateStaticParams`.
 * We emit a single `_` placeholder per dynamic route, so `useParams()`
 * always returns `{alias: "_"}` (or `{token: "_"}`) at runtime — the
 * SPA never sees the real segment from the URL bar. This hook reads
 * `window.location.pathname` instead.
 *
 * Usage example:
 *   const alias = useRouteSegment("/s/");   // for /s/abc123
 *   const token = useRouteSegment("/register-with-invite/");
 *
 * On the server / during build the function returns "" — every caller
 * is in a `"use client"` component that already guards on an empty
 * value (loading screens, password modal closed, etc.).
 */
export function useRouteSegment(prefix: string): string {
  // useState's lazy initialiser runs once per mount, on the client. We
  // skip during SSR/build via the typeof check so Next.js doesn't choke
  // when pre-rendering the placeholder HTML.
  const [value] = useState<string>(() => {
    if (typeof window === "undefined") return "";
    return extractSegment(window.location.pathname, prefix);
  });
  return value;
}
