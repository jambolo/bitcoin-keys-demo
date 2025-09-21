// Global type declarations for polyfills

declare global {
  interface Window {
    process: typeof import('process')
  }
}

export {}