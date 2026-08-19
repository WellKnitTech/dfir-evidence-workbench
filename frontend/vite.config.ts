import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiTarget = process.env.DFIRWB_API_TARGET ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/__dev__": apiTarget,
      "/api": apiTarget,
      "/health": apiTarget,
    },
  },
  preview: {
    proxy: {
      "/__dev__": apiTarget,
      "/api": apiTarget,
      "/health": apiTarget,
    },
  },
});
