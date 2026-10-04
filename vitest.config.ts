import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";

/**
 * Отдельная конфигурация тестов.
 *
 * AUDIT 3.1.1: раньше конфигурации не было вовсе, окружение задавалось
 * прагмой `// @vitest-environment jsdom` в каждом файле. Достаточно было
 * забыть её в новом тесте, чтобы DOM-тест упал с невнятной ошибкой. Теперь
 * jsdom включён глобально, а прагмы в существующих файлах безвредны.
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  test: {
    environment: "jsdom",
    globals: false,
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
    clearMocks: true,
    coverage: {
      provider: "v8",
      reportsDirectory: "coverage",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/locales/**", "src/vite-env.d.ts"],
      reporter: ["text-summary", "lcov"],
      // Пороги стоят только на слоях с бизнес-логикой: хуки хранилища,
      // библиотеки и переиспользуемые контролы. Экраны — это преимущественно
      // разметка, гнаться за процентом там дороже, чем полезно; их поведение
      // проверяется точечными тестами (см. RecordEdit.test.tsx).
      thresholds: {
        "src/lib/**": { statements: 65, lines: 65, branches: 70, functions: 25 },
        "src/screens/vault/**": {
          statements: 90,
          lines: 90,
          branches: 85,
          functions: 90,
        },
        "src/components/ui/**": {
          statements: 60,
          lines: 60,
          branches: 50,
          functions: 60,
        },
      },
    },
  },
});
