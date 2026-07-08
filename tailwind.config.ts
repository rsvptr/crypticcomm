import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-geist-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        // Surface scale for the dark theme. Page background lives in globals.css.
        surface: {
          DEFAULT: "#111116", // panels and cards
          inset: "#0c0c11", // code blocks, text areas, recessed fields
          raised: "#17171e", // hover states, chips
        },
      },
      keyframes: {
        pop: {
          "0%": { transform: "scale(0.5)", opacity: "0.4" },
          "100%": { transform: "scale(1)", opacity: "1" },
        },
      },
      animation: {
        // Icon-swap feedback (copy buttons, unread dot). Guarded globally by
        // the prefers-reduced-motion rule in globals.css.
        pop: "pop 0.25s cubic-bezier(0.16, 1, 0.3, 1)",
      },
    },
  },
  plugins: [],
};

export default config;
