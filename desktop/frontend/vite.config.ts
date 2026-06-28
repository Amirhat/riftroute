/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Vite serves the UI from disk in dev (hot reload) and builds to dist/ for the
// embedded release bundle. Wails drives this via wails.json (frontend:dev /
// frontend:build). The dev server URL is negotiated by Wails ("auto").
export default defineConfig({
  plugins: [react()],
  // Relative base so the embedded assets load under the Wails asset server.
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  // Headless smoke tests (Vitest + jsdom). Runs the pure UI helpers and a couple
  // of leaf-component renders; the full app needs the Wails runtime so it is not
  // mounted here.
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
