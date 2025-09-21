// Browser polyfills for Node.js crypto libraries
import { Buffer } from 'buffer'
import process from 'process'

// Get reliable reference to global object
const globalRef = (function() {
  if (typeof globalThis !== 'undefined') return globalThis
  if (typeof window !== 'undefined') return window
  if (typeof global !== 'undefined') return global
  if (typeof self !== 'undefined') return self
  throw new Error('Unable to locate global object')
})()

// Make Buffer available globally in all possible ways
globalRef.Buffer = Buffer
globalRef.global = globalRef.global || globalRef
globalRef.process = process

// Handle the specific "buffer_1.Buffer" pattern that causes the error
globalRef.buffer_1 = { Buffer, alloc: Buffer.alloc }

// For window environments
if (typeof window !== 'undefined') {
  ;(window as any).Buffer = Buffer
  ;(window as any).process = process
  ;(window as any).global = window
  ;(window as any).buffer_1 = { Buffer, alloc: Buffer.alloc }
}

// For globalThis environments
if (typeof globalThis !== 'undefined') {
  ;(globalThis as any).Buffer = Buffer
  ;(globalThis as any).process = process
  ;(globalThis as any).buffer_1 = { Buffer, alloc: Buffer.alloc }
}

// For Node-style global
if (typeof global !== 'undefined') {
  ;(global as any).Buffer = Buffer
  ;(global as any).process = process
  ;(global as any).buffer_1 = { Buffer, alloc: Buffer.alloc }
}

// Handle module-style exports for CommonJS compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Buffer, alloc: Buffer.alloc }
  module.exports.Buffer = Buffer
}

// Verify polyfills are working
try {
  const testBuffer = Buffer.from('test', 'utf8')
  if (testBuffer.toString() !== 'test') {
    console.warn('Buffer polyfill may not be working correctly')
  }
  
  // Test the specific buffer_1.Buffer.alloc pattern from the error
  if (globalRef.buffer_1 && globalRef.buffer_1.Buffer && globalRef.buffer_1.Buffer.alloc) {
    const testAlloc = globalRef.buffer_1.Buffer.alloc(4)
    if (!testAlloc || testAlloc.length !== 4) {
      console.warn('buffer_1.Buffer.alloc polyfill may not be working correctly')
    }
  }
} catch (error) {
  console.error('Buffer polyfill verification failed:', error)
}

export { Buffer, process }