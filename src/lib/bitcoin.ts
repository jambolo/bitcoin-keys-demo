import './polyfills'
import * as bitcoin from 'bitcoinjs-lib'
import * as bip39 from 'bip39'
import bs58 from 'bs58'
import { ECPairFactory } from 'ecpair'
import * as tinysecp256k1 from 'tiny-secp256k1'
import { Buffer } from '@/lib/polyfills'

// Initialize ECPair with tiny-secp256k1
let ECPair: any
try {
  ECPair = ECPairFactory(tinysecp256k1)
} catch (error) {
  console.error('Failed to initialize ECPair:', error)
  throw error
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

export function generateRandomPrivateKey(): string {
  const keyPair = ECPair.makeRandom()
  return keyPair.toWIF()
}

export function isValidHex(hex: string, expectedLength?: number): boolean {
  if (!hex || typeof hex !== 'string') return false
  if (!/^[0-9a-fA-F]*$/.test(hex)) return false
  if (expectedLength && hex.length !== expectedLength) return false
  return true
}

export function privateKeyFromWif(wif: string): BitcoinKeyData | null {
  if (!wif || typeof wif !== 'string') return null
  
  try {
    const keyPair = ECPair.fromWIF(wif)
    if (!keyPair.publicKey) return null
    
    const compressed = keyPair.compressed
    const privateKeyHex = keyPair.privateKey ? Buffer.from(keyPair.privateKey).toString('hex') : undefined
    const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex')
    const hash160Buffer = bitcoin.crypto.hash160(Buffer.from(keyPair.publicKey))
    const publicKeyHash = Buffer.from(hash160Buffer).toString('hex')
    
    // Generate addresses using bitcoinjs-lib
    const p2pkh = bitcoin.payments.p2pkh({ pubkey: Buffer.from(keyPair.publicKey) })
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(keyPair.publicKey) })
    const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh })
    
    // For Taproot, we need to handle it differently as it's a newer format
    let taprootAddress = 'N/A'
    try {
      const p2tr = bitcoin.payments.p2tr({ pubkey: Buffer.from(keyPair.publicKey).subarray(1, 33) })
      taprootAddress = p2tr.address || 'N/A'
    } catch {
      // Taproot generation failed, use N/A
    }

    return {
      privateKeyWif: wif,
      privateKeyHex,
      compressed,
      publicKeyHex,
      publicKeyHash,
      p2pkhAddress: p2pkh.address || 'N/A',
      p2shAddress: p2sh.address || 'N/A',
      bech32Address: p2wpkh.address || 'N/A',
      taprootAddress
    }
  } catch {
    return null
  }
}

export function privateKeyFromHex(hex: string): BitcoinKeyData | null {
  if (!hex || typeof hex !== 'string') return null
  
  try {
    if (!isValidHex(hex, 64)) return null
    const keyPair = ECPair.fromPrivateKey(Buffer.from(hex, 'hex'))
    return privateKeyFromWif(keyPair.toWIF())
  } catch {
    return null
  }
}

export function encodeWif(privateKeyHex: string, compressed: boolean = true): string | null {
  if (!privateKeyHex || typeof privateKeyHex !== 'string') return null
  
  try {
    if (!isValidHex(privateKeyHex, 64)) return null
    
    const keyPair = ECPair.fromPrivateKey(
      Buffer.from(privateKeyHex, 'hex'),
      { compressed }
    )
    return keyPair.toWIF()
  } catch {
    return null
  }
}

export function decodeWif(wif: string): { privateKeyHex: string; compressed: boolean; checksum: string; valid: boolean } | null {
  if (!wif || typeof wif !== 'string') return null
  
  try {
    // First validate using ECPair
    const keyPair = ECPair.fromWIF(wif)
    
    // Manually decode to get checksum
    const decoded = bs58.decode(wif)
    const checksum = Buffer.from(decoded.subarray(-4)).toString('hex')
    
    if (!keyPair.privateKey) {
      return null
    }
    
    return {
      privateKeyHex: Buffer.from(keyPair.privateKey).toString('hex'),
      compressed: keyPair.compressed,
      checksum,
      valid: true
    }
  } catch {
    return null
  }
}

export function validateWif(wif: string): { valid: boolean; error?: string } {
  if (!wif || typeof wif !== 'string') {
    return { valid: false, error: 'Invalid input' }
  }
  
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

    // Try to decode and validate
    try {
      ECPair.fromWIF(wif)
      return { valid: true }
    } catch (error: any) {
      if (error.message.includes('Invalid checksum')) {
        return { valid: false, error: 'Checksum mismatch' }
      }
      if (error.message.includes('Invalid prefix')) {
        return { valid: false, error: 'Invalid prefix' }
      }
      return { valid: false, error: 'Invalid WIF format' }
    }
  } catch {
    return { valid: false, error: 'Invalid WIF format' }
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

  try {
    ECPair.fromPublicKey(Buffer.from(pubkeyHex, 'hex'))
    return { valid: true }
  } catch {
    return { valid: false, error: 'Invalid public key' }
  }
}

export function validateBitcoinAddress(address: string): { valid: boolean; error?: string } {
  try {
    bitcoin.address.toOutputScript(address)
    return { valid: true }
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
        const decoded = bitcoin.address.fromBech32(address)
        
        let type = 'Unknown SegWit'
        if (decoded.version === 0) {
          if (decoded.data.length === 20) {
            type = 'P2WPKH (Native SegWit v0)'
          } else if (decoded.data.length === 32) {
            type = 'P2WSH (Native SegWit v0)'
          }
        } else if (decoded.version === 1 && decoded.data.length === 32) {
          type = 'P2TR (Taproot)'
        } else {
          type = `SegWit v${decoded.version}`
        }
        
        return {
          type,
          hash: Buffer.from(decoded.data).toString('hex'),
          witnessVersion: decoded.version
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

export function generateMiniKey(): string {
  const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  
  // Generate random mini keys until we find one that passes the check
  let attempts = 0
  const maxAttempts = 100000
  
  while (attempts < maxAttempts) {
    // Start with 'S' and generate 29 random characters
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
  
  // If we somehow fail after 100k attempts (extremely unlikely), 
  // generate using a different approach
  while (true) {
    try {
      let miniKey = 'S'
      // Use crypto.getRandomValues for better randomness
      const randomBytes = new Uint8Array(29)
      crypto.getRandomValues(randomBytes)
      
      for (let i = 0; i < 29; i++) {
        miniKey += chars[randomBytes[i] % chars.length]
      }
      
      const checkStr = miniKey + '?'
      const hash = bitcoin.crypto.sha256(Buffer.from(checkStr, 'utf8'))
      if (hash[0] === 0) {
        return miniKey
      }
    } catch (error) {
      // Continue trying
    }
  }
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