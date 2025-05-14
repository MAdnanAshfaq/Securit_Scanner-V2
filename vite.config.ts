import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [
    react(),
    ...(process.env.NODE_ENV === "development" && process.env.REPL_ID !== undefined
      ? [
          // Only load Replit plugins in development mode
          import("@replit/vite-plugin-runtime-error-modal").then((m) => m.default()),
          import("@replit/vite-plugin-cartographer").then((m) => m.cartographer()),
        ]
      : []),
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),
      'crypto-js': 'crypto-js/lib/crypto-js.js',
    },
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
    rollupOptions: {
      external: ['crypto-js', 'crypto-js/*'],
    },
  },
  optimizeDeps: {
    include: ['crypto-js'],
  },
});
