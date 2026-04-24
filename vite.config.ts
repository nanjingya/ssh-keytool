import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

export default defineConfig({
  plugins: [
    tailwindcss(),
    vue(),
    AutoImport({
      resolvers: [ElementPlusResolver()],
      imports: ['vue', 'vue-router', 'pinia'],
      dts: 'src/auto-imports.d.ts',
    }),
    Components({
      resolvers: [ElementPlusResolver()],
      dts: 'src/components.d.ts',
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  define: {
    global: 'globalThis',
  },
  optimizeDeps: {
    include: ['bcrypt-pbkdf', 'buffer'],
  },
  build: {
    // Raise warning threshold — forge + noble are known-large vendor libs
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          // node-forge: RSA/MD5/PEM — heaviest dep (~900KB raw)
          if (id.includes('node_modules/node-forge')) return 'vendor-forge'
          // @noble: Ed25519 + hashes (~60KB)
          if (id.includes('node_modules/@noble')) return 'vendor-noble'
          // bcrypt-pbkdf + buffer polyfill (~80KB)
          if (id.includes('node_modules/bcrypt-pbkdf') || id.includes('node_modules/buffer')) {
            return 'vendor-bcrypt'
          }
          // Element Plus component library (keep separate for long-term caching)
          if (id.includes('node_modules/element-plus')) return 'vendor-element'
        },
      },
    },
  },
})
