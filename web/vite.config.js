import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../src/research_compute_network/web_dist",
    emptyOutDir: true,
  },
  test: { environment: "node", include: ["src/**/*.test.{js,jsx}"] },
});
