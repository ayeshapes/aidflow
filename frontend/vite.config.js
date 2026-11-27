import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,          // listen on 0.0.0.0 so the browser can reach the container
    port: 5173,
    strictPort: true,    // fail instead of silently choosing another port
    watch: { usePolling: true }, // file-change detection that works in Docker on Windows/WSL
    // The browser calls /api on THIS server; Vite forwards it to the backend.
    // The browser therefore sees one origin and no cross-origin request happens.
    // "backend" is the Compose service name.
    proxy: {
      "/api": {
        target: process.env.VITE_PROXY_TARGET || "http://backend:8000",
        changeOrigin: true,
      },
    },
  },
});
