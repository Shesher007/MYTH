import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Detect Tauri build environment
const isTauri = !!process.env.TAURI_ENV_PLATFORM;

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],

  // Tauri expects a fixed port for dev
  clearScreen: false,
  envPrefix: ['VITE_', 'TAURI_ENV_*'],

  server: {
    port: 5173,
    strictPort: true,
    allowedHosts: true, // Industrial Grade: Allow dynamic Cloudflare tunnel hosts
    // Tauri requires internal host for IPC
    host: isTauri ? '127.0.0.1' : undefined,
  },

  // Optimizations for ultra-fast desktop app
  build: {
    // Tauri uses Chromium on Windows/Linux, WebKit on macOS
    target: 'esnext',
    // Produce smaller bundles for desktop
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: !isTauri, // Keep console in desktop for sidecar logs
        drop_debugger: true,
      },
    },
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          motion: ['framer-motion'],
        },
      },
    },
    chunkSizeWarningLimit: 1000,
  },
})
