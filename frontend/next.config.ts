import type { NextConfig } from "next";

const isProd = process.env.NODE_ENV === "production";
const internalHost = process.env.TAURI_DEV_HOST || "localhost";

const nextConfig: NextConfig = {
  // Required for Tauri — static export only (no Node server)
  output: "export",

  // Image optimization doesn't work with static export
  images: {
    unoptimized: true,
  },

  // Helps asset resolution during `tauri dev`
  assetPrefix: isProd ? undefined : `http://${internalHost}:3000`,
};

export default nextConfig;
