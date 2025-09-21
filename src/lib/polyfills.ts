// Browser polyfills for Node.js crypto libraries
import { Buffer as BufferPolyfill } from 'buffer'
import process from 'process'

// Get reliable reference to global object
const globalRef = (function() {
  if (typeof globalThis !== 'undefined') return globalThis
  if (typeof window !== 'undefined') return window
  if (typeof global !== 'undefined') return global
  if (typeof self !== 'undefined') return self
  throw new Error('Unable to locate global object')
})()

// Set up all possible global references with comprehensive error handling
try {
  globalRef.Buffer = BufferPolyfill
  globalRef.global = globalRef
  globalRef.process = process
} catch (e) {
  console.warn('Failed to set up some global polyfills:', e)
}

// For module resolution patterns that cause externalization errors
if (typeof window !== 'undefined') {
  try {
    ;(window as any).Buffer = BufferPolyfill
    ;(window as any).process = process
    ;(window as any).global = window
  } catch (e) {
    console.warn('Failed to set up window polyfills:', e)
  }
}

if (typeof globalThis !== 'undefined') {
  try {
    ;(globalThis as any).Buffer = BufferPolyfill
    ;(globalThis as any).process = process
  } catch (e) {
    console.warn('Failed to set up globalThis polyfills:', e)
  }
}

if (typeof global !== 'undefined') {
  try {
    ;(global as any).Buffer = BufferPolyfill
    ;(global as any).process = process
  } catch (e) {
    console.warn('Failed to set up global polyfills:', e)
  }
}

// Handle potential module exports patterns
try {
  // For dynamic imports that might look for buffer module
  ;(globalRef as any)['buffer'] = { Buffer: BufferPolyfill }
  ;(globalRef as any)['Buffer'] = BufferPolyfill
} catch (e) {
  // Ignore errors during polyfill setup
}

// Export for direct use
export const Buffer = BufferPolyfill
export { process }
export default BufferPolyfill