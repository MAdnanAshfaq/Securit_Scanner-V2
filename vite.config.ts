import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// Only import Replit plugins in development
const replitPlugins = process.env.NODE_ENV === "development" ? [
  require("@replit/vite-plugin-runtime-error-modal"),
  require("@replit/vite-plugin-cartographer")
] : [];

export default defineConfig({
  plugins: [
    react(),
    ...replitPlugins
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),
    },
  },
  root: path.resolve(import.meta.dirname, "client"),
  server: {
    port: 3000,
    host: "localhost"
  },
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
  },
});
