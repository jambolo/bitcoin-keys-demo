// Global type declarations for polyfills

declare global {
  interface Window {
    Buffer: typeof import('buffer').Buffer
    process: typeof import('process')
  }
}

export {}