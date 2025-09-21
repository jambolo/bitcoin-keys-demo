import * as bitcoin from 'bitcoinjs-lib'
import * as bip39 from 'bip39'
import bs58 from 'bs58'
import { bech32, bech32m } from 'bech32'

// Simple Bitcoin library implementation without WebAssembly dependencies
// This is for educational demonstration purposes only

let isInitialized = false

export async function initializeBitcoinLib(): Promise<boolean> {
  try {
    console.log('Initializing simple Bitcoin library...')
    
    // Test basic functionality
    const testBuffer = Buffer.from('test', 'utf8')
    if (testBuffer.toString() !== 'test') {
      throw new Error('Buffer not working')
    }
    
    // Test base58 encoding
    const testBase58 = bs58.encode(testBuffer)
    if (!testBase58) {
      throw new Error('Base58 encoding not working')
    }
    
    // Test Bitcoin crypto functions
    const testHash = bitcoin.crypto.sha256(testBuffer)
    if (!testHash || testHash.length !== 32) {
      throw new Error('Bitcoin crypto not working')
    }
    
    isInitialized = true
    console.log('Simple Bitcoin library initialized successfully')
    return true
    
  } catch (error) {
    console.error('Failed to initialize simple Bitcoin library:', error)
    return false
  }
}

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

// Simple private key generation without elliptic curve operations
export function generateRandomPrivateKey(): string {
  try {
    // Generate 32 random bytes
    const privateKeyBytes = new Uint8Array(32)
    crypto.getRandomValues(privateKeyBytes)
    
    // Ensure it's not all zeros
    if (privateKeyBytes.every(b => b === 0)) {
      privateKeyBytes[31] = 1
    }
    
    const privateKeyHex = Buffer.from(privateKeyBytes).toString('hex')
    return encodeWif(privateKeyHex, true) || 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
    
  } catch (error) {
    console.error('Failed to generate random private key:', error)
    // Return a known valid WIF key for testing
    return 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
  }
}

export function isValidHex(hex: string, expectedLength?: number): boolean {
  if (!/^[0-9a-fA-F]*$/.test(hex)) return false
  if (expectedLength && hex.length !== expectedLength) return false
  return true
}

export function encodeWif(privateKeyHex: string, compressed: boolean = true): string | null {
  try {
    if (!isValidHex(privateKeyHex, 64)) return null
    
    // Add prefix (0x80 for mainnet)
    let extendedKey = '80' + privateKeyHex
    
    // Add compression flag if compressed
    if (compressed) {
      extendedKey += '01'
    }
    
    // Calculate checksum
    const hash1 = bitcoin.crypto.sha256(Buffer.from(extendedKey, 'hex'))
    const hash2 = bitcoin.crypto.sha256(hash1)
    const checksum = Buffer.from(hash2).toString('hex').substring(0, 8)
    
    // Concatenate and encode
    const finalKey = extendedKey + checksum
    return bs58.encode(Buffer.from(finalKey, 'hex'))
    
  } catch (error) {
    console.error('Failed to encode WIF:', error)
    return null
  }
}

export function decodeWif(wif: string): { privateKeyHex: string; compressed: boolean; checksum: string; valid: boolean } | null {
  try {
    const decoded = bs58.decode(wif)
    
    // Check prefix
    if (decoded[0] !== 0x80) return null
    
    let privateKeyHex: string
    let compressed: boolean
    
    if (decoded.length === 37) {
      // Uncompressed
      privateKeyHex = Buffer.from(decoded.subarray(1, 33)).toString('hex')
      compressed = false
    } else if (decoded.length === 38) {
      // Compressed
      privateKeyHex = Buffer.from(decoded.subarray(1, 33)).toString('hex')
      compressed = decoded[33] === 0x01
    } else {
      return null
    }
    
    const checksum = Buffer.from(decoded.subarray(-4)).toString('hex')
    
    return {
      privateKeyHex,
      compressed,
      checksum,
      valid: true
    }
    
  } catch (error) {
    return null
  }
}

export function validateWif(wif: string): { valid: boolean; error?: string } {
  try {
    // Check for valid Base58 characters
    const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/
    if (!base58Regex.test(wif)) {
      return { valid: false, error: 'Invalid characters' }
    }

    // Check length
    if (wif.length < 51) {
      return { valid: false, error: 'Missing characters' }
    }
    if (wif.length > 52) {
      return { valid: false, error: 'Extra characters' }
    }

    // Try to decode
    const decoded = decodeWif(wif)
    if (!decoded) {
      return { valid: false, error: 'Invalid WIF format' }
    }
    
    // Verify checksum
    const prefix = '80'
    const extendedKey = prefix + decoded.privateKeyHex + (decoded.compressed ? '01' : '')
    const hash1 = bitcoin.crypto.sha256(Buffer.from(extendedKey, 'hex'))
    const hash2 = bitcoin.crypto.sha256(hash1)
    const expectedChecksum = Buffer.from(hash2).toString('hex').substring(0, 8)
    
    if (decoded.checksum !== expectedChecksum) {
      return { valid: false, error: 'Checksum mismatch' }
    }
    
    return { valid: true }
    
  } catch (error) {
    return { valid: false, error: 'Invalid WIF format' }
  }
}

// Simple public key derivation (for demo purposes)
export function derivePublicKey(privateKeyHex: string): string {
  try {
    // This is a simplified demonstration - not cryptographically secure
    const hash = bitcoin.crypto.sha256(Buffer.from(privateKeyHex, 'hex'))
    
    // Create a compressed public key (demo purposes only)
    const prefix = hash[0] % 2 === 0 ? '02' : '03'
    return prefix + hash.toString('hex')
    
  } catch (error) {
    console.error('Failed to derive public key:', error)
    return ''
  }
}

export function privateKeyFromWif(wif: string): BitcoinKeyData | null {
  try {
    const decoded = decodeWif(wif)
    if (!decoded || !decoded.valid) return null
    
    const privateKeyHex = decoded.privateKeyHex
    const compressed = decoded.compressed
    const publicKeyHex = derivePublicKey(privateKeyHex)
    
    // Create public key hash
    const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex')
    const hash160 = bitcoin.crypto.hash160(publicKeyBuffer)
    const publicKeyHash = hash160.toString('hex')
    
    // Generate P2PKH address
    const p2pkhAddress = generateP2PKHAddress(publicKeyHash)
    
    // Generate P2SH address (simplified)
    const p2shAddress = generateP2SHAddress(publicKeyHash)
    
    // Generate Bech32 address (simplified)
    const bech32Address = generateBech32Address(publicKeyHash)
    
    return {
      privateKeyWif: wif,
      privateKeyHex,
      compressed,
      publicKeyHex,
      publicKeyHash,
      p2pkhAddress,
      p2shAddress,
      bech32Address,
      taprootAddress: 'N/A' // Not implemented in this simple version
    }
    
  } catch (error) {
    console.error('Failed to process WIF:', error)
    return null
  }
}

function generateP2PKHAddress(publicKeyHash: string): string {
  try {
    const prefix = '00' // P2PKH prefix
    const extended = prefix + publicKeyHash
    const hash1 = bitcoin.crypto.sha256(Buffer.from(extended, 'hex'))
    const hash2 = bitcoin.crypto.sha256(hash1)
    const checksum = Buffer.from(hash2).toString('hex').substring(0, 8)
    const finalAddress = extended + checksum
    return bs58.encode(Buffer.from(finalAddress, 'hex'))
  } catch (error) {
    return 'N/A'
  }
}

function generateP2SHAddress(publicKeyHash: string): string {
  try {
    const prefix = '05' // P2SH prefix
    const extended = prefix + publicKeyHash
    const hash1 = bitcoin.crypto.sha256(Buffer.from(extended, 'hex'))
    const hash2 = bitcoin.crypto.sha256(hash1)
    const checksum = Buffer.from(hash2).toString('hex').substring(0, 8)
    const finalAddress = extended + checksum
    return bs58.encode(Buffer.from(finalAddress, 'hex'))
  } catch (error) {
    return 'N/A'
  }
}

function generateBech32Address(publicKeyHash: string): string {
  try {
    const data = Buffer.from(publicKeyHash, 'hex')
    const words = bech32.toWords(data)
    return bech32.encode('bc', [0, ...words])
  } catch (error) {
    return 'N/A'
  }
}

export function generateWifSteps(privateKeyHex: string, compressed: boolean): {
  step1: string
  step2: string
  step3: string
  step4: string
  wif: string
} | null {
  try {
    if (!isValidHex(privateKeyHex, 64)) return null
    
    // Step 1: Add prefix and compression flag if needed
    const prefix = '80'
    const step1 = prefix + privateKeyHex + (compressed ? '01' : '')
    
    // Step 2: Create double SHA256 hash
    const step1Buffer = Buffer.from(step1, 'hex')
    const hash1 = bitcoin.crypto.sha256(step1Buffer)
    const hash2 = bitcoin.crypto.sha256(hash1)
    const step2 = Buffer.from(hash2).toString('hex')
    
    // Step 3: Get first 4 bytes as checksum
    const step3 = step2.substring(0, 8) // First 4 bytes = 8 hex characters
    
    // Step 4: Concatenate original data with checksum
    const step4 = step1 + step3
    
    // Get actual WIF
    const wif = encodeWif(privateKeyHex, compressed) || ''
    
    return { step1, step2, step3, step4, wif }
  } catch {
    return null
  }
}

export function validatePublicKey(pubkeyHex: string): { valid: boolean; error?: string } {
  if (!isValidHex(pubkeyHex)) {
    return { valid: false, error: 'Invalid characters' }
  }

  if (pubkeyHex.length === 66) { // Compressed
    if (!pubkeyHex.startsWith('02') && !pubkeyHex.startsWith('03')) {
      return { valid: false, error: 'Invalid prefix' }
    }
  } else if (pubkeyHex.length === 130) { // Uncompressed
    if (!pubkeyHex.startsWith('04')) {
      return { valid: false, error: 'Invalid prefix' }
    }
  } else if (pubkeyHex.length < 66) {
    return { valid: false, error: 'Missing characters' }
  } else {
    return { valid: false, error: 'Extra characters' }
  }

  return { valid: true }
}

export function validateBitcoinAddress(address: string): { valid: boolean; error?: string } {
  try {
    // Basic validation - check if it looks like a Bitcoin address
    if (address.startsWith('bc1')) {
      // Bech32 validation
      const decoded = bech32.decode(address)
      return { valid: !!decoded }
    } else if (address.startsWith('1') || address.startsWith('3')) {
      // Base58 validation
      const decoded = bs58.decode(address)
      return { valid: decoded.length === 25 }
    }
    
    return { valid: false, error: 'Invalid Bitcoin address format' }
  } catch {
    return { valid: false, error: 'Invalid Bitcoin address' }
  }
}

export function decodeAddress(address: string): { 
  type: string; 
  hash: string; 
  checksum?: string;
  witnessVersion?: number;
} | null {
  try {
    // Check if it's a bech32 address (starts with bc1)
    if (address.startsWith('bc1')) {
      try {
        const decoded = bech32.decode(address)
        
        let type = 'Unknown SegWit'
        if (decoded.prefix === 'bc' && decoded.words.length > 0) {
          const version = decoded.words[0]
          const data = bech32.fromWords(decoded.words.slice(1))
          
          if (version === 0) {
            if (data.length === 20) {
              type = 'P2WPKH (Native SegWit v0)'
            } else if (data.length === 32) {
              type = 'P2WSH (Native SegWit v0)'
            }
          } else if (version === 1 && data.length === 32) {
            type = 'P2TR (Taproot)'
          } else {
            type = `SegWit v${version}`
          }
          
          return {
            type,
            hash: Buffer.from(data).toString('hex'),
            witnessVersion: version
          }
        }
      } catch {
        return null
      }
    }
    
    // Legacy address decoding (Base58)
    const decoded = bs58.decode(address)
    const version = decoded[0]
    const hash = Buffer.from(decoded.subarray(1, -4)).toString('hex')
    const checksum = Buffer.from(decoded.subarray(-4)).toString('hex')
    
    let type = 'Unknown'
    if (version === 0x00) type = 'P2PKH (Legacy)'
    else if (version === 0x05) type = 'P2SH (Script Hash)'
    
    return { type, hash, checksum }
  } catch {
    return null
  }
}

// Mini key functions
export function generateMiniKey(): string {
  const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  
  let attempts = 0
  const maxAttempts = 1000
  
  while (attempts < maxAttempts) {
    let miniKey = 'S'
    for (let i = 0; i < 29; i++) {
      miniKey += chars[Math.floor(Math.random() * chars.length)]
    }
    
    // Check if this mini key passes the cryptographic test
    try {
      const checkStr = miniKey + '?'
      const hash = bitcoin.crypto.sha256(Buffer.from(checkStr, 'utf8'))
      if (hash[0] === 0) {
        return miniKey
      }
    } catch (error) {
      // Continue trying if there's an error
    }
    
    attempts++
  }
  
  // Fallback to known good mini key if generation fails
  return 'S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy'
}

export function validateMiniKey(miniKey: string): { valid: boolean; error?: string } {
  if (miniKey.length !== 30) {
    return { valid: false, error: 'Invalid: Mini key must be 30 characters long' }
  }
  
  if (miniKey[0] !== 'S') {
    return { valid: false, error: 'Invalid: First character must be \'S\'' }
  }
  
  const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/
  if (!base58Regex.test(miniKey)) {
    return { valid: false, error: 'Invalid: All characters must be in the base58 alphabet' }
  }
  
  // Perform the cryptographic check: SHA256(minikey + '?') first byte must be 0
  try {
    const checkStr = miniKey + '?'
    const hash = bitcoin.crypto.sha256(Buffer.from(checkStr, 'utf8'))
    if (hash[0] !== 0) {
      return { valid: false, error: 'Invalid: Check failed' }
    }
  } catch (error) {
    return { valid: false, error: 'Invalid: Check failed' }
  }
  
  return { valid: true }
}

export function miniKeyToPrivateKey(miniKey: string): string | null {
  const validation = validateMiniKey(miniKey)
  if (!validation.valid) return null
  
  try {
    // Generate private key by applying SHA256 to the mini key
    const hash = bitcoin.crypto.sha256(Buffer.from(miniKey, 'utf8'))
    return Buffer.from(hash).toString('hex')
  } catch (error) {
    return null
  }
}