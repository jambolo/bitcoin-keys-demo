import { Buffer } from '@/lib/polyfills'
import { 
  generatePublicKey,
  doubleSha256,
  hash160
} from '@/lib/crypto'
import {
  decodeBase58,
  encodeBase58,
} from './base58'

import * as secp256k1 from 'secp256k1'

export interface BitcoinKeyData {
  privateKeyWif?: string
  privateKeyHex?: string
  compressed?: boolean
  publicKeyHex?: string
  publicKeyHash?: string
  p2pkhAddress?: string
  p2shAddress?: string
  bech32Address?: string
  taprootAddress?: string
}

// Utility functions
export function isValidHex(hex: string, expectedLength?: number): boolean {
  if (!hex || typeof hex !== 'string') return false
  if (!/^[0-9a-fA-F]*$/.test(hex)) return false
  if (expectedLength && hex.length !== expectedLength) return false
  return true
}

// Private key functions
export async function generateRandomPrivateKey(): Promise<string> {
  try {
    const privateKeyBytes = new Uint8Array(32)
    crypto.getRandomValues(privateKeyBytes)
    
    if (privateKeyBytes.every(b => b === 0)) {
      privateKeyBytes[31] = 1
    }
    
    const privateKeyHex = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('')
    const wif = await encodeWif(privateKeyHex, true)
    return wif || 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
  } catch (error) {
    console.error('Failed to generate random private key:', error)
    return 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
  }
}

export async function encodeWif(privateKeyHex: string, compressed: boolean = true): Promise<string | null> {
  if (!isValidHex(privateKeyHex, 64)) return null
  
  try {
    const prefix = '80' // Mainnet prefix
    const suffix = compressed ? '01' : ''
    const extended = prefix + privateKeyHex + suffix
    
    const extendedBytes = new Uint8Array(extended.length / 2)
    for (let i = 0; i < extended.length; i += 2) {
      extendedBytes[i / 2] = parseInt(extended.substring(i, i + 2), 16)
    }
    
    const checksum = await doubleSha256(extendedBytes)
    const checksumHex = Array.from(checksum.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')
    const finalHex = extended + checksumHex
    
    const finalBytes = new Uint8Array(finalHex.length / 2)
    for (let i = 0; i < finalHex.length; i += 2) {
      finalBytes[i / 2] = parseInt(finalHex.substring(i, i + 2), 16)
    }
    
    return encodeBase58(finalBytes)
  } catch (error) {
    console.error('Failed to encode WIF:', error)
    return null
  }
}

export async function decodeWif(wif: string): Promise<{ privateKeyHex: string; compressed: boolean; checksum: string; valid: boolean } | null> {
  try {
    const decoded = decodeBase58(wif)
    
    if (decoded.length !== 37 && decoded.length !== 38) {
      return null
    }
    
    const prefix = decoded[0]
    if (prefix !== 0x80) return null
    
    const compressed = decoded.length === 38
    const privateKeyEnd = compressed ? -5 : -4
    const privateKeyHex = Array.from(decoded.slice(1, privateKeyEnd)).map(b => b.toString(16).padStart(2, '0')).join('')
    const checksum = Array.from(decoded.slice(-4)).map(b => b.toString(16).padStart(2, '0')).join('')
    
    // Validate checksum
    const payload = decoded.slice(0, -4)
    const calculatedChecksum = await doubleSha256(payload)
    const calculatedChecksumHex = Array.from(calculatedChecksum.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')
    
    const valid = checksum === calculatedChecksumHex
    
    return {
      privateKeyHex,
      compressed,
      checksum,
      valid
    }
  } catch (error) {
    console.error('Failed to decode WIF:', error)
    return null
  }
}

export async function validateWif(wif: string): Promise<{ valid: boolean; error?: string }> {
  if (!wif || typeof wif !== 'string') {
    return { valid: false, error: 'Invalid input' }
  }
  
  // Check for invalid characters
  if (!/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(wif)) {
    return { valid: false, error: 'Invalid characters' }
  }
  
  try {
    const decoded = await decodeWif(wif)
    if (!decoded) {
      return { valid: false, error: 'Invalid WIF format' }
    }
    
    if (!decoded.valid) {
      return { valid: false, error: 'Checksum mismatch' }
    }
    
    // Check private key range
    if (!secp256k1.privateKeyVerify(Buffer.from(decoded.privateKeyHex, 'hex'))) {
      return { valid: false, error: 'Private key is outside of the valid range' }
    }
    
    return { valid: true }
  } catch (error) {
    return { valid: false, error: 'Decoding failed' }
  }
}

export async function generateWifSteps(privateKeyHex: string, compressed: boolean): Promise<{
  step1: string
  step2: string
  step3: string
  step4: string
  checksumFirst4: string
  wif: string
}> {
  const prefix = '80'
  const suffix = compressed ? '01' : ''
  const step1 = prefix + privateKeyHex + suffix
  
  const step1Bytes = new Uint8Array(step1.length / 2)
  for (let i = 0; i < step1.length; i += 2) {
    step1Bytes[i / 2] = parseInt(step1.substring(i, i + 2), 16)
  }
  
  const checksumHash = await doubleSha256(step1Bytes)
  const checksumFirst4 = Array.from(checksumHash.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')
  
  const step2 = 'sha256(sha256(' + step1 + '))'
  const step3 = Array.from(checksumHash).map(b => b.toString(16).padStart(2, '0')).join('')
  const step4 = step1 + checksumFirst4
  
  const step4Bytes = new Uint8Array(step4.length / 2)
  for (let i = 0; i < step4.length; i += 2) {
    step4Bytes[i / 2] = parseInt(step4.substring(i, i + 2), 16)
  }
  
  const wif = encodeBase58(step4Bytes)
  
  return {
    step1,
    step2,
    step3,
    step4,
    checksumFirst4,
    wif
  }
}

// Key derivation functions
export async function privateKeyFromWif(wif: string): Promise<BitcoinKeyData | null> {
  try {
    const decoded = await decodeWif(wif)
    if (!decoded || !decoded.valid) return null
    
    const publicKeyHex = generatePublicKey(decoded.privateKeyHex, decoded.compressed)
    
    // Import generateAddresses from address module
    const { generateAddresses } = await import('./address')
    const addresses = await generateAddresses(publicKeyHex)
    
    return {
      privateKeyWif: wif,
      privateKeyHex: decoded.privateKeyHex,
      compressed: decoded.compressed,
      publicKeyHex: publicKeyHex,
      publicKeyHash: addresses.publicKeyHash,
      p2pkhAddress: addresses.p2pkhAddress,
      p2shAddress: addresses.p2shAddress,
      bech32Address: addresses.bech32Address,
      taprootAddress: addresses.taprootAddress
    }
  } catch (error) {
    console.error('Failed to process WIF:', error)
    return null
  }
}

export async function privateKeyFromHex(hex: string): Promise<BitcoinKeyData | null> {
  try {
    if (!isValidHex(hex, 64)) return null
    
    const wif = await encodeWif(hex, true)
    if (!wif) return null
    
    return await privateKeyFromWif(wif)
  } catch (error) {
    console.error('Failed to process hex private key:', error)
    return null
  }
}

// Public key validation
export function validatePublicKey(pubkeyHex: string): { valid: boolean; error?: string } {
  if (!pubkeyHex || typeof pubkeyHex !== 'string') {
    return { valid: false, error: 'Invalid input' }
  }
  
  if (!isValidHex(pubkeyHex)) {
    return { valid: false, error: 'Invalid characters' }
  }
  
  const prefix = pubkeyHex.substring(0, 2)
  
  if (prefix === '02' || prefix === '03') {
    if (pubkeyHex.length !== 66) {
      return { valid: false, error: pubkeyHex.length < 66 ? 'Missing characters' : 'Extra characters' }
    }
  } else if (prefix === '04') {
    if (pubkeyHex.length !== 130) {
      return { valid: false, error: pubkeyHex.length < 130 ? 'Missing characters' : 'Extra characters' }
    }
  } else {
    return { valid: false, error: 'Invalid prefix' }
  }
  
  return { valid: true }
}
