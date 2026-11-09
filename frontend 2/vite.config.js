
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const securityHeaders = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'"
  ].join("; ")
};

export default defineConfig({
  plugins: [react()],

  server: {
    port: 5173
  },

  preview: {
    port: 5173,
    strictPort: true,
    headers: securityHeaders
  }
});
