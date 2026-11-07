/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './client/src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        vault: {
          bg: '#090D16',
          card: '#111827',
          border: '#1F2937',
          accent: '#10B981',
        },
      },
    },
  },
  plugins: [],
};
