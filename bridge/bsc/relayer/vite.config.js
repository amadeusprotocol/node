// Bundles the bridge page into public/, which the worker serves (worker/index.js injects the settings)
import { defineConfig } from 'vite'

export default defineConfig({
  root: 'frontend',
  build: { outDir: '../public', emptyOutDir: true, target: 'es2022' },
})
