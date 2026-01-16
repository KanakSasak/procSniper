/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'ps-dark': '#1a1a2e',
        'ps-darker': '#16213e',
        'ps-accent': '#0f3460',
        'ps-primary': '#e94560',
      },
    },
  },
  plugins: [],
}
