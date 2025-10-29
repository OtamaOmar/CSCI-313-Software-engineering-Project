/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class', // <---- THIS LINE IS CRUCIAL
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#10b981', // emerald green
      },
    },
  },
  plugins: [],
}