import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Конфигурация Vite для Tauri.
// Tauri ожидает frontendDist по пути dist/ и dev-server на 1420.
export default defineConfig(async () => ({
  plugins: [react()],

  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },

  // Vite слушает на фиксированном порту, чтобы Tauri ровно подключался.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    watch: {
      // Игнорируем изменения в src-tauri (этим занимается cargo watch).
      ignored: ["**/src-tauri/**"],
    },
  },

  // Совместимость с Tauri: ESBuild target.
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "esnext",
    minify: "esbuild",
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
}));
