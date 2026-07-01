import type { NextConfig } from "next";

// Static export: `next build` emits a fully static site into ./out, which the
// Go server serves from ./web (single-binary deploy, unchanged). Data is fetched
// client-side from the same-origin Fides API (/api/v1/...).
// PORTAL_BASE_PATH lets us serve the export under a sub-path (e.g. "/next") for
// side-by-side QA next to the existing portal. Empty = served at root.
const basePath = process.env.PORTAL_BASE_PATH || "";

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
  basePath: basePath || undefined,
  assetPrefix: basePath || undefined,
};

export default nextConfig;
