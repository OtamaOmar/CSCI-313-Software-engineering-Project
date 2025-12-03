import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Everything starting with /api will go to your Node backend
      '/api': 'http://localhost:4000',
    },
  },
});
