// Browser polyfills for Node.js crypto libraries
import { Buffer } from 'buffer'
import process from 'process'

// Set up global references immediately
const globalRef = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : {} as any

// Ensure Buffer is available at multiple levels
globalRef.Buffer = Buffer
if (typeof window !== 'undefined') {
  ;(window as any).Buffer = Buffer
  ;(window as any).process = process
}
if (typeof globalThis !== 'undefined') {
  ;(globalThis as any).Buffer = Buffer
  ;(globalThis as any).process = process
}

// Also ensure it's available as a module global for CommonJS-style requires
if (typeof global !== 'undefined') {
  ;(global as any).Buffer = Buffer
  ;(global as any).process = process
}

// Verify polyfills are working
try {
  const testBuffer = Buffer.from('test', 'utf8')
  if (testBuffer.toString() !== 'test') {
    console.warn('Buffer polyfill may not be working correctly')
  }
} catch (error) {
  console.error('Buffer polyfill failed:', error)
}

export { Buffer, process }