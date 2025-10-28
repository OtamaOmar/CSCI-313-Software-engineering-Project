/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
      },
      colors: {
        brand: {
          light: "#6ee7b7",
          DEFAULT: "#10b981",
          dark: "#047857",
        },
        text: {
          light: "#111827",  // near-black for readability for light mode
          dark: "#f9fafb",   // near-white for dark mode
          mutedLight: "#6b7280",
          mutedDark: "#d1d5db",
        },
      },
    },
  },
  plugins: [],
};