import type { NextConfig } from "next";

// Static export: `next build` emits a fully static site into ./out, which the
// Go server serves from ./web (single-binary deploy, unchanged). Data is fetched
// client-side from the same-origin Fides API (/api/v1/...).
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
