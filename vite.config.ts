import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig, PluginOption } from "vite";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

import sparkPlugin from "@github/spark/spark-vite-plugin";
import createIconImportProxy from "@github/spark/vitePhosphorIconProxyPlugin";
import { resolve } from 'path'

const projectRoot = process.env.PROJECT_ROOT || import.meta.dirname

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    wasm(),
    topLevelAwait(),
    tailwindcss(),
    // DO NOT REMOVE
    createIconImportProxy() as PluginOption,
    sparkPlugin() as PluginOption,
  ],
  resolve: {
    alias: {
      '@': resolve(projectRoot, 'src'),
      buffer: 'buffer',
      crypto: 'crypto-browserify',
      stream: 'stream-browserify',
      process: 'process/browser',
    }
  },
  optimizeDeps: {
    exclude: ['tiny-secp256k1'],
    include: ['buffer', 'crypto-browserify', 'stream-browserify', 'process', 'bip39', 'bitcoinjs-lib', 'ecpair', 'bs58']
  },
  define: {
    global: 'globalThis',
    'process.env': {},
  }
});
