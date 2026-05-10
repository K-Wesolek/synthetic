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
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
        serif: [
          "Charter",
          "Iowan Old Style",
          "Source Serif 4",
          "ui-serif",
          "Georgia",
          "serif",
        ],
      },
      colors: {
        canvas: "rgb(var(--canvas) / <alpha-value>)",
        surface: {
          DEFAULT: "rgb(var(--surface) / <alpha-value>)",
          2: "rgb(var(--surface-2) / <alpha-value>)",
          3: "rgb(var(--surface-3) / <alpha-value>)",
        },
        border: {
          DEFAULT: "rgb(var(--border) / <alpha-value>)",
          strong: "rgb(var(--border-strong) / <alpha-value>)",
        },
        fg: {
          primary: "rgb(var(--fg-primary) / <alpha-value>)",
          secondary: "rgb(var(--fg-secondary) / <alpha-value>)",
          tertiary: "rgb(var(--fg-tertiary) / <alpha-value>)",
          muted: "rgb(var(--fg-muted) / <alpha-value>)",
        },
        sev: {
          high: "rgb(var(--sev-high) / <alpha-value>)",
          "high-bg": "var(--sev-high-bg)",
          medium: "rgb(var(--sev-medium) / <alpha-value>)",
          "medium-bg": "var(--sev-medium-bg)",
          low: "rgb(var(--sev-low) / <alpha-value>)",
          "low-bg": "var(--sev-low-bg)",
          info: "rgb(var(--sev-info) / <alpha-value>)",
          "info-bg": "var(--sev-info-bg)",
          opt: "rgb(var(--sev-opt) / <alpha-value>)",
          "opt-bg": "var(--sev-opt-bg)",
        },
        accent: {
          DEFAULT: "rgb(var(--accent) / <alpha-value>)",
          soft: "var(--accent-soft)",
        },
      },
      letterSpacing: {
        tightish: "-0.012em",
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.04em" }],
      },
    },
  },
  plugins: [],
};
export default config;
