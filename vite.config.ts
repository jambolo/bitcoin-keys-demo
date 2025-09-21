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
    wasm(),
    topLevelAwait(),
    react(),
    tailwindcss(),
    // DO NOT REMOVE
    createIconImportProxy() as PluginOption,
    sparkPlugin() as PluginOption,
  ],
  resolve: {
    alias: {
      '@': resolve(projectRoot, 'src'),
      buffer: 'buffer',
      process: 'process/browser',
      util: 'util',
    }
  },
  define: {
    global: 'globalThis',
    'process.env': {},
    'require': 'undefined'
  },
  optimizeDeps: {
    include: ['bitcoinjs-lib', 'bip39', 'bs58', 'ecpair', 'bip32', 'tiny-secp256k1', 'buffer', 'process/browser', 'util'],
    exclude: []
  }
});
