/** @type {import('tailwindcss').Config} */
// Дизайн-токены Vaultisor. Палитра — бренд-бук MFASOFT 2022.
// Vaultisor использует только цветовую систему и типографику бренд-бука,
// без логотипов и упоминания материнской компании.
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Основной акцент — фирменный teal.
        brand: {
          50: "#E5F6F5",
          100: "#C2EAE7",
          200: "#8FD8D2",
          300: "#5CC4BD",
          400: "#2EB1A8",
          500: "#0CA49F", // primary
          600: "#0A8A86",
          700: "#08706C",
          800: "#065652",
          900: "#043C3A",
        },
        // База
        ink: {
          950: "#0F0F0F",
          900: "#191919", // base dark
          800: "#262626",
          700: "#333333",
          600: "#4D4D4D", // neutral 1
          500: "#666666",
          400: "#808080", // neutral 2
          300: "#A6A6A6",
          200: "#CCCCCC",
          100: "#E6E6E6",
          50: "#F5F5F5",
        },
        // Дополнительный акцент (использовать редко: статусы, badge)
        accent: {
          50: "#FFF1E8",
          100: "#FFE0CC",
          200: "#FFC299",
          300: "#FFAD7E",
          400: "#FF9E63", // brand orange
          500: "#FF8845",
          600: "#E5732C",
          700: "#B85A1F",
        },
        // Семантические
        danger: "#E5484D",
        warning: "#F5A623",
        success: "#22C55E",
        info: "#3B82F6",
      },
      fontFamily: {
        sans: [
          "Roboto",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Arial",
          "sans-serif",
        ],
        serif: ["Noto Serif", "Georgia", "serif"],
        mono: [
          "JetBrains Mono",
          "Cascadia Code",
          "Consolas",
          "Menlo",
          "monospace",
        ],
      },
      fontSize: {
        // Mobile-friendly шкала.
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.01em" }],
        xs: ["0.75rem", { lineHeight: "1.125rem" }],
        sm: ["0.8125rem", { lineHeight: "1.25rem" }],
        base: ["0.9375rem", { lineHeight: "1.5rem" }],
        lg: ["1.0625rem", { lineHeight: "1.625rem" }],
        xl: ["1.25rem", { lineHeight: "1.75rem" }],
        "2xl": ["1.5rem", { lineHeight: "2rem", letterSpacing: "-0.01em" }],
        "3xl": ["1.875rem", { lineHeight: "2.25rem", letterSpacing: "-0.02em" }],
      },
      spacing: {
        // Дополнительные шаги для компактного UI.
        "4.5": "1.125rem",
        "5.5": "1.375rem",
        "13": "3.25rem",
        "15": "3.75rem",
        "17": "4.25rem",
      },
      borderRadius: {
        xl: "0.875rem",
        "2xl": "1.125rem",
        "3xl": "1.5rem",
      },
      boxShadow: {
        soft: "0 1px 2px 0 rgba(0,0,0,0.05), 0 1px 3px 0 rgba(0,0,0,0.04)",
        card: "0 4px 16px -4px rgba(0,0,0,0.08), 0 2px 4px -2px rgba(0,0,0,0.04)",
        modal:
          "0 24px 48px -12px rgba(0,0,0,0.45), 0 8px 16px -8px rgba(0,0,0,0.30)",
        glow: "0 0 0 4px rgba(12,164,159,0.15)",
        "glow-strong": "0 0 0 6px rgba(12,164,159,0.25)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: 0 },
          to: { opacity: 1 },
        },
        "fade-in-up": {
          from: { opacity: 0, transform: "translateY(8px)" },
          to: { opacity: 1, transform: "translateY(0)" },
        },
        "scale-in": {
          from: { opacity: 0, transform: "scale(0.96)" },
          to: { opacity: 1, transform: "scale(1)" },
        },
        shake: {
          "0%,100%": { transform: "translateX(0)" },
          "20%,60%": { transform: "translateX(-6px)" },
          "40%,80%": { transform: "translateX(6px)" },
        },
        "spin-slow": {
          to: { transform: "rotate(360deg)" },
        },
      },
      animation: {
        "fade-in": "fade-in 200ms ease-out",
        "fade-in-up": "fade-in-up 240ms cubic-bezier(0.2, 0.8, 0.2, 1)",
        "scale-in": "scale-in 200ms cubic-bezier(0.2, 0.8, 0.2, 1)",
        shake: "shake 320ms ease-in-out",
        "spin-slow": "spin-slow 2.4s linear infinite",
      },
    },
  },
  plugins: [],
};
