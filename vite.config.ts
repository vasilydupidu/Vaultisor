import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { readFileSync } from "node:fs";

/**
 * Единый источник правды для Content-Security-Policy.
 *
 * AUDIT 3.1.1: политика жила в двух местах — в tauri.conf.json и отдельной
 * копией в index.html. Копии разошлись (в meta не было `'self'` и
 * `tauri.localhost` в connect-src), а в dev-режиме meta-политика блокировала
 * inline-preamble React Refresh и WebSocket HMR. Теперь production-сборка
 * подставляет ровно ту же строку, что применяет рантайм Tauri, а в dev тег
 * удаляется и действует только рантайм-политика Tauri.
 */
function cspPlugin(isDev: boolean): Plugin {
  const configPath = path.resolve(import.meta.dirname, "src-tauri/tauri.conf.json");
  const tauriConfig = JSON.parse(readFileSync(configPath, "utf8"));
  const csp: string = tauriConfig?.app?.security?.csp ?? "";
  if (!csp && !isDev) {
    throw new Error("tauri.conf.json: app.security.csp is required for production builds");
  }
  return {
    name: "vaultisor-csp",
    transformIndexHtml(html) {
      if (isDev) {
        return html.replace(
          /\s*<meta http-equiv="Content-Security-Policy"[^>]*\/>/,
          "",
        );
      }
      return html.replace("__VAULTISOR_CSP__", csp);
    },
  };
}

// Конфигурация Vite для Tauri.
// Tauri ожидает frontendDist по пути dist/ и dev-server на 1420.
export default defineConfig(async ({ command }) => ({
  plugins: [react(), cspPlugin(command === "serve")],

  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
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
    minify: "oxc",
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
}));
