/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        null: {
          bg: '#03030a',
          surface: '#0a0a14',
          border: '#1a1a2e',
          primary: '#00ffaa',
          'primary-dim': 'rgba(0, 255, 170, 0.3)',
          accent: '#ff00aa',
          danger: '#ff0044',
          warning: '#ffaa00',
          success: '#00ff44',
          info: '#00aaff',
          text: '#e0e0e0',
          muted: '#555555',
        }
      },
      fontFamily: {
        display: ['Orbitron', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        body: ['Space Grotesk', 'sans-serif'],
      },
      animation: {
        'glow': 'glow 2s ease-in-out infinite',
        'scan': 'scan 8s linear infinite',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
      },
      keyframes: {
        glow: {
          '0%, 100%': { boxShadow: '0 0 20px rgba(0, 255, 170, 0.4)' },
          '50%': { boxShadow: '0 0 40px rgba(0, 255, 170, 0.6)' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        }
      },
      backgroundImage: {
        'scanline': 'repeating-linear-gradient(transparent 0px, transparent 2px, rgba(0,0,0,0.1) 2px, rgba(0,0,0,0.1) 4px)',
        'grid': 'linear-gradient(rgba(0, 255, 170, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 170, 0.03) 1px, transparent 1px)',
      }
    },
  },
  plugins: [],
}
