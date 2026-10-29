import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // Keep the Host header as localhost:5173 (changeOrigin: false) so the backend
      // sees the same origin as the browser: cookies stay first-party and the
      // OAuth redirect_uri / CSRF origin checks line up with what the user sees.
      "/api": { target: "http://localhost:3000", changeOrigin: false },
    },
  },
});
