// Browser polyfills for Node.js modules
import { Buffer as BufferPoly } from 'buffer'
import ProcessPoly from 'process'

// Ensure global Buffer and process are available before anything else
if (typeof globalThis !== 'undefined') {
  // @ts-ignore
  globalThis.global = globalThis
  // @ts-ignore  
  globalThis.Buffer = BufferPoly
  // @ts-ignore
  globalThis.process = ProcessPoly
  // @ts-ignore
  globalThis.require = (module: string) => {
    throw new Error(`require() is not supported in the browser for module: ${module}`)
  }
}

if (typeof window !== 'undefined') {
  // @ts-ignore
  window.global = window
  // @ts-ignore
  window.Buffer = BufferPoly
  // @ts-ignore
  window.process = ProcessPoly
  // @ts-ignore
  window.require = (module: string) => {
    throw new Error(`require() is not supported in the browser for module: ${module}`)
  }
}

// Re-export for modules that need them
export { BufferPoly as Buffer }
export { ProcessPoly as process }