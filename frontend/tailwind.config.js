/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // SentinelX brand palette
        sentinel: {
          bg:        '#0E1117',
          surface:   '#171B22',
          surface2:  '#1F2530',
          border:    '#2D3642',
          borderLt:  '#3A4150',
          text:      '#F8FAFC',
          textSec:   '#94A3B8',
          textMuted: '#64748B',
          accent:    '#16A34A',
          accentHov: '#15803D',
          warning:   '#D97706',
          critical:  '#DC2626',
          info:      '#475569',
        },
        // Backward compat
        soc: {
          bg:        '#0E1117',
          surface:   '#171B22',
          secondary: '#1F2530',
          border:    '#2D3642',
          hover:     '#252D3A',
        },
        text: {
          primary:   '#F8FAFC',
          secondary: '#94A3B8',
          muted:     '#64748B',
          disabled:  '#475569',
        },
        accent: {
          green:   '#16A34A',
          success: '#16A34A',
          warning: '#D97706',
          danger:  '#DC2626',
          info:    '#475569',
          amber:   '#D97706',
        },
      },
      fontFamily: {
        sans: ['Inter', 'IBM Plex Sans', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      spacing: {
        '4.5': '1.125rem',
        '18':  '4.5rem',
        '22':  '5.5rem',
      },
      borderRadius: {
        xl:  '0.75rem',
        '2xl': '1rem',
      },
      fontSize: {
        '2xs': ['0.625rem', '0.875rem'],
      },
      width: {
        sidebar:      '240px',
        'sidebar-sm': '64px',
      },
      animation: {
        'fade-in':     'fadeIn 0.2s ease-out',
        'slide-up':    'slideUp 0.25s ease-out',
        'slide-right': 'slideRight 0.2s ease-out',
        'live-pulse':  'livePulse 2s ease-in-out infinite',
        'ping-dot':    'ping 1.4s cubic-bezier(0,0,0.2,1) infinite',
      },
      keyframes: {
        fadeIn: {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        slideUp: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        slideRight: {
          from: { opacity: '0', transform: 'translateX(-8px)' },
          to:   { opacity: '1', transform: 'translateX(0)' },
        },
        livePulse: {
          '0%, 100%': { opacity: '1',   transform: 'scale(1)' },
          '50%':      { opacity: '0.5', transform: 'scale(0.85)' },
        },
      },
    },
  },
  plugins: [],
}
