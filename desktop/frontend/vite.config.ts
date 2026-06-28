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
})
