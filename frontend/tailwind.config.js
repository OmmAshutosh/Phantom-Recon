/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        phantom: {
          bg: '#070a0f',
          surface: '#0d131f',
          card: '#111927',
          border: '#1b263b',
          borderLight: '#24324d',
          mint: '#34d399',
          mintDark: '#059669',
          mintGlow: 'rgba(52, 211, 153, 0.15)',
          textDim: '#94a3b8',
          textMuted: '#64748b'
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif']
      }
    },
  },
  plugins: [],
}
