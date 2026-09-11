/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Space Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        forest: {
          950: '#07130e',
          900: '#0e241c',
          800: '#15382b',
          700: '#1b4a39',
          500: '#10b981',
          400: '#34d399',
        },
        earth: {
          900: '#2b1b17',
          800: '#42281d',
          600: '#8c5338',
          400: '#d97736',
          300: '#e59866',
        }
      }
    },
  },
  plugins: [],
}