/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // App canvas & elevated surface hierarchy matching screenshot
        obsidian: {
          DEFAULT: "#F1F5F9", // Canvas background
          900: "#FFFFFF",     // Primary card & sidebar background
          800: "#F8FAFC",     // Light interactive hover & feed strip
          700: "#E2E8F0",     // Border dividers & stroke lines
          600: "#94A3B8",     // Placeholder & muted timestamps
          500: "#64748B",     // Secondary text & subtitles
          400: "#334155",     // Body text
          300: "#0F172A",     // Primary bold headings
        },
        cyber: {
          cyan: "#2563EB",    // Primary corporate blue (CT icon, active nav, links)
          crimson: "#DC2626", // Threat red (Critical badges, threat count)
          amber: "#F59E0B",   // Warning amber (Incidents, open alerts)
          emerald: "#10B981", // Connected status & health rate
          purple: "#7C3AED",  // Sandbox tag
        },
        border: "#E2E8F0",
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "Consolas",
          "Menlo",
          "monospace",
        ],
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
      },
      boxShadow: {
        "card-sm": "0 1px 3px rgba(15, 23, 42, 0.04), 0 1px 2px rgba(15, 23, 42, 0.02)",
        "card-md": "0 4px 6px -1px rgba(15, 23, 42, 0.05), 0 2px 4px -2px rgba(15, 23, 42, 0.03)",
        "active-nav": "0 1px 2px rgba(37, 99, 235, 0.08)",
      },
    },
  },
  plugins: [],
};