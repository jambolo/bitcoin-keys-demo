// Core cryptographic primitives and elliptic curve operations for Bitcoin
let crypto: Crypto = (typeof window !== 'undefined' && window.crypto) || (typeof globalThis !== 'undefined' && (globalThis as any).crypto)

if (!crypto) {
  throw new Error('Crypto module not available')
}

// Use secp256k1 for all EC operations
import * as secp256k1 from 'secp256k1'


// Generate public key from private key using secp256k1
export function generatePublicKey(privateKeyHex: string, compressed: boolean = true): string {
  if (privateKeyHex.length != 64) {
    throw new Error('Invalid private key hex')
  }
  const privateKey = new Uint8Array(privateKeyHex.length / 2)
  for (let i = 0; i < privateKeyHex.length; i += 2) {
    privateKey[i / 2] = parseInt(privateKeyHex.substring(i, i + 2), 16)
  }
  if (!secp256k1.privateKeyVerify(privateKey)) {
    throw new Error('Private key out of range')
  }
  const publicKey = secp256k1.publicKeyCreate(privateKey, compressed)
  return Buffer.from(publicKey).toString('hex')
}

// Cryptographic hash functions
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Ensure input is a Uint8Array backed by ArrayBuffer
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer)
}

export async function doubleSha256(data: Uint8Array): Promise<Uint8Array> {
  const hash1 = await sha256(data)
  return await sha256(hash1)
}

// RIPEMD-160 using Node.js crypto (browser-compatible via dynamic import)
export function ripemd160(data: Uint8Array): Uint8Array {
  // Use Node.js crypto if available, otherwise throw
  try {
    // Dynamically require to avoid issues in browser builds
    // @ts-ignore
    const crypto = require('crypto')
    const hash = crypto.createHash('ripemd160').update(Buffer.from(data)).digest()
    return new Uint8Array(hash)
  } catch (e) {
    throw new Error('RIPEMD-160 is not available in this environment')
  }
}

// Hash160 (SHA256 then RIPEMD160)
export async function hash160(data: Uint8Array): Promise<Uint8Array> {
  const sha256Hash = await sha256(data)
  return ripemd160(sha256Hash)
}
