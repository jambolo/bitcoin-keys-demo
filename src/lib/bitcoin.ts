import { Buffer } from '@/lib/polyfills'

// Unified Bitcoin library combining functionality from bitcoin-lite, bitcoin-simple, and bitcoin
// Browser-compatible implementation for educational demonstration

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

// SECP256K1 curve parameters
const CURVE_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
const P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F')
const A = BigInt(0)
const B = BigInt(7)
const GX = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
const GY = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')

// Point on elliptic curve
interface Point {
  x: bigint
  y: bigint
}

// Modular arithmetic helpers
function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m]
  let [old_s, s] = [1n, 0n]
  
  while (r !== 0n) {
    const quotient = old_r / r
    ;[old_r, r] = [r, old_r - quotient * r]
    ;[old_s, s] = [s, old_s - quotient * s]
  }
  
  return ((old_s % m) + m) % m
}

// Elliptic curve point operations
function pointAdd(p1: Point, p2: Point): Point {
  if (p1.x === p2.x && p1.y === p2.y) {
    // Point doubling
    const s = ((3n * p1.x * p1.x + A) * modInverse(2n * p1.y, P)) % P
    const x3 = (s * s - 2n * p1.x) % P
    const y3 = (s * (p1.x - x3) - p1.y) % P
    return { x: (x3 + P) % P, y: (y3 + P) % P }
  } else {
    // Point addition
    const s = ((p2.y - p1.y) * modInverse(p2.x - p1.x, P)) % P
    const x3 = (s * s - p1.x - p2.x) % P
    const y3 = (s * (p1.x - x3) - p1.y) % P
    return { x: (x3 + P) % P, y: (y3 + P) % P }
  }
}

function pointMultiply(k: bigint, point: Point): Point {
  if (k === 0n) throw new Error('Cannot multiply by zero')
  if (k === 1n) return point
  
  let result = point
  let addend = point
  k = k - 1n
  
  while (k > 0n) {
    if (k & 1n) {
      result = pointAdd(result, addend)
    }
    addend = pointAdd(addend, addend)
    k = k >> 1n
  }
  
  return result
}

// Base58 encoding/decoding
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

export function base58Encode(buffer: Uint8Array): string {
  let num = BigInt('0x' + Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join(''))
  let encoded = ''
  
  while (num > 0) {
    const remainder = num % 58n
    num = num / 58n
    encoded = BASE58_ALPHABET[Number(remainder)] + encoded
  }
  
  // Add leading zeros
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    encoded = '1' + encoded
  }
  
  return encoded
}

function base58Decode(str: string): Uint8Array {
  let num = 0n
  for (let i = 0; i < str.length; i++) {
    const char = str[i]
    const index = BASE58_ALPHABET.indexOf(char)
    if (index === -1) throw new Error(`Invalid character: ${char}`)
    num = num * 58n + BigInt(index)
  }
  
  const hex = num.toString(16)
  const bytes = hex.length % 2 === 0 ? hex : '0' + hex
  const result = new Uint8Array(bytes.length / 2)
  
  for (let i = 0; i < bytes.length; i += 2) {
    result[i / 2] = parseInt(bytes.substring(i, i + 2), 16)
  }
  
  // Add leading zeros
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    const zeros = new Uint8Array(result.length + 1)
    zeros.set(result, 1)
    return zeros
  }
  
  return result
}

// Cryptographic hash functions
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(hashBuffer)
}

export async function doubleSha256(data: Uint8Array): Promise<Uint8Array> {
  const hash1 = await sha256(data)
  return await sha256(hash1)
}

// Simplified RIPEMD-160 implementation
function ripemd160(data: Uint8Array): Uint8Array {
  // Initialize hash values
  let h0 = 0x67452301
  let h1 = 0xEFCDAB89
  let h2 = 0x98BADCFE
  let h3 = 0x10325476
  let h4 = 0xC3D2E1F0
  
  // Pre-process message
  const message = new Uint8Array(data.length + 1 + 8)
  message.set(data)
  message[data.length] = 0x80
  
  // Set length in bits as 64-bit little-endian
  const bitLength = data.length * 8
  const view = new DataView(message.buffer)
  view.setUint32(message.length - 8, bitLength, true)
  view.setUint32(message.length - 4, Math.floor(bitLength / 0x100000000), true)
  
  // Process message in 512-bit chunks
  for (let chunk = 0; chunk < message.length; chunk += 64) {
    const w = new Uint32Array(16)
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(chunk + i * 4, true)
    }
    
    // Main loop (simplified)
    let [a, b, c, d, e] = [h0, h1, h2, h3, h4]
    
    for (let i = 0; i < 80; i++) {
      let f: number
      let k: number
      
      if (i < 16) {
        f = (b ^ c ^ d) >>> 0
        k = 0x00000000
      } else if (i < 32) {
        f = ((b & c) | (~b & d)) >>> 0
        k = 0x5A827999
      } else if (i < 48) {
        f = ((b | ~c) ^ d) >>> 0
        k = 0x6ED9EBA1
      } else if (i < 64) {
        f = ((b & d) | (c & ~d)) >>> 0
        k = 0x8F1BBCDC
      } else {
        f = (b ^ (c | ~d)) >>> 0
        k = 0xA953FD4E
      }
      
      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[i % 16]) >>> 0
      e = d
      d = c
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = temp
    }
    
    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
  }
  
  // Produce final hash value as little-endian
  const result = new Uint8Array(20)
  const resultView = new DataView(result.buffer)
  resultView.setUint32(0, h0, true)
  resultView.setUint32(4, h1, true)
  resultView.setUint32(8, h2, true)
  resultView.setUint32(12, h3, true)
  resultView.setUint32(16, h4, true)
  
  return result
}

// Hash160 (SHA256 then RIPEMD160)
async function hash160(data: Uint8Array): Promise<Uint8Array> {
  const sha256Hash = await sha256(data)
  return ripemd160(sha256Hash)
}

// Generate public key from private key
function generatePublicKey(privateKeyHex: string, compressed: boolean = true): string {
  const privateKeyInt = BigInt('0x' + privateKeyHex)
  
  if (privateKeyInt <= 0n || privateKeyInt >= CURVE_ORDER) {
    throw new Error('Private key out of range')
  }
  
  const generator = { x: GX, y: GY }
  const publicKeyPoint = pointMultiply(privateKeyInt, generator)
  
  if (compressed) {
    const prefix = publicKeyPoint.y % 2n === 0n ? '02' : '03'
    return prefix + publicKeyPoint.x.toString(16).padStart(64, '0')
  } else {
    return '04' + publicKeyPoint.x.toString(16).padStart(64, '0') + publicKeyPoint.y.toString(16).padStart(64, '0')
  }
}

// Bech32 encoding for SegWit addresses
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

function bech32Polymod(values: number[]): number {
  const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  
  for (const value of values) {
    const top = chk >> 25
    chk = (chk & 0x1ffffff) << 5 ^ value
    for (let i = 0; i < 5; i++) {
      chk ^= ((top >> i) & 1) ? GENERATOR[i] : 0
    }
  }
  
  return chk
}

function bech32HrpExpand(hrp: string): number[] {
  const hrpHi = hrp.split('').map(char => char.charCodeAt(0) >> 5)
  const hrpLo = hrp.split('').map(char => char.charCodeAt(0) & 31)
  return [...hrpHi, 0, ...hrpLo]
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data]
  const polymod = bech32Polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1
  const checksum: number[] = []
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> 5 * (5 - i)) & 31)
  }
  return checksum
}

function bech32Encode(hrp: string, data: number[]): string {
  const checksum = bech32CreateChecksum(hrp, data)
  const combined = [...data, ...checksum]
  return hrp + '1' + combined.map(d => BECH32_CHARSET[d]).join('')
}

function bech32Decode(bech32str: string): { prefix: string; words: number[] } | null {
  try {
    const pos = bech32str.lastIndexOf('1')
    if (pos === -1 || pos === 0 || pos + 7 > bech32str.length) {
      return null
    }
    
    const hrp = bech32str.substring(0, pos)
    const data = bech32str.substring(pos + 1)
    
    const decoded: number[] = []
    for (const char of data) {
      const index = BECH32_CHARSET.indexOf(char)
      if (index === -1) return null
      decoded.push(index)
    }
    
    return { prefix: hrp, words: decoded.slice(0, -6) }
  } catch {
    return null
  }
}

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean = true): number[] {
  let acc = 0
  let bits = 0
  const result: number[] = []
  const maxv = (1 << toBits) - 1
  const maxAcc = (1 << (fromBits + toBits - 1)) - 1
  
  for (const value of data) {
    if (value < 0 || value >> fromBits) {
      throw new Error('Invalid data for base conversion')
    }
    acc = ((acc << fromBits) | value) & maxAcc
    bits += fromBits
    while (bits >= toBits) {
      bits -= toBits
      result.push((acc >> bits) & maxv)
    }
  }
  
  if (pad) {
    if (bits) {
      result.push((acc << (toBits - bits)) & maxv)
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    throw new Error('Invalid padding in base conversion')
  }
  
  return result
}

// Generate addresses from public key hash
export async function generateAddresses(publicKeyHex: string): Promise<{
  p2pkhAddress: string
  p2shAddress: string
  bech32Address: string
  taprootAddress: string
  publicKeyHash: string
}> {
  const publicKeyBytes = new Uint8Array(publicKeyHex.length / 2)
  for (let i = 0; i < publicKeyHex.length; i += 2) {
    publicKeyBytes[i / 2] = parseInt(publicKeyHex.substring(i, i + 2), 16)
  }
  
  const publicKeyHash = await hash160(publicKeyBytes)
  const publicKeyHashHex = Array.from(publicKeyHash).map(b => b.toString(16).padStart(2, '0')).join('')
  
  // P2PKH Address (Legacy)
  const p2pkhPayload = new Uint8Array(21)
  p2pkhPayload[0] = 0x00 // Mainnet prefix
  p2pkhPayload.set(publicKeyHash, 1)
  const p2pkhChecksum = await doubleSha256(p2pkhPayload)
  const p2pkhWithChecksum = new Uint8Array(25)
  p2pkhWithChecksum.set(p2pkhPayload)
  p2pkhWithChecksum.set(p2pkhChecksum.slice(0, 4), 21)
  const p2pkhAddress = base58Encode(p2pkhWithChecksum)
  
  // P2SH Address (Script Hash)
  const p2shPayload = new Uint8Array(21)
  p2shPayload[0] = 0x05 // P2SH prefix
  p2shPayload.set(publicKeyHash, 1)
  const p2shChecksum = await doubleSha256(p2shPayload)
  const p2shWithChecksum = new Uint8Array(25)
  p2shWithChecksum.set(p2shPayload)
  p2shWithChecksum.set(p2shChecksum.slice(0, 4), 21)
  const p2shAddress = base58Encode(p2shWithChecksum)
  
  // Bech32 Address (SegWit v0)
  const witnessVersion = 0
  const witnessProgram = Array.from(publicKeyHash)
  const bech32Data = convertBits([witnessVersion, ...witnessProgram], 8, 5)
  const bech32Address = bech32Encode('bc', bech32Data)
  
  // Taproot Address (SegWit v1) - simplified implementation
  const taprootData = convertBits([1, ...Array.from(publicKeyHash), ...new Array(12).fill(0)], 8, 5)
  const taprootAddress = bech32Encode('bc', taprootData)
  
  return {
    p2pkhAddress,
    p2shAddress,
    bech32Address,
    taprootAddress,
    publicKeyHash: publicKeyHashHex
  }
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
    
    return base58Encode(finalBytes)
  } catch (error) {
    console.error('Failed to encode WIF:', error)
    return null
  }
}

export async function decodeWif(wif: string): Promise<{ privateKeyHex: string; compressed: boolean; checksum: string; valid: boolean } | null> {
  try {
    const decoded = base58Decode(wif)
    
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
    const privateKeyInt = BigInt('0x' + decoded.privateKeyHex)
    if (privateKeyInt <= 0n || privateKeyInt >= CURVE_ORDER) {
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
  
  const wif = base58Encode(step4Bytes)
  
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

// Address validation and decoding
export async function validateBitcoinAddress(address: string): Promise<{ valid: boolean; error?: string }> {
  if (!address || typeof address !== 'string') {
    return { valid: false, error: 'Invalid input' }
  }
  
  try {
    if (address.startsWith('bc1')) {
      // Bech32 validation
      const decoded = bech32Decode(address)
      if (!decoded) {
        return { valid: false, error: 'Invalid bech32 format' }
      }
      return { valid: true }
    } else if (address.startsWith('1') || address.startsWith('3')) {
      // Base58 validation
      try {
        const decoded = base58Decode(address)
        if (decoded.length !== 25) {
          return { valid: false, error: 'Invalid address length' }
        }
        
        // Verify checksum
        const payload = decoded.slice(0, 21)
        const checksum = decoded.slice(21)
        const calculatedChecksum = await doubleSha256(payload)
        const expectedChecksum = Array.from(calculatedChecksum.slice(0, 4))
        
        for (let i = 0; i < 4; i++) {
          if (checksum[i] !== expectedChecksum[i]) {
            return { valid: false, error: 'Checksum mismatch' }
          }
        }
        
        return { valid: true }
      } catch {
        return { valid: false, error: 'Invalid base58 format' }
      }
    }
    
    return { valid: false, error: 'Invalid address format' }
  } catch {
    return { valid: false, error: 'Invalid address' }
  }
}

export function decodeAddress(address: string): { 
  type: string
  hash: string
  checksum: string
} | null {
  try {
    if (address.startsWith('bc1')) {
      // Bech32 address
      const decoded = bech32Decode(address)
      if (!decoded) return null
      
      let type = 'Bech32 (SegWit)'
      if (decoded.words.length > 0) {
        const version = decoded.words[0]
        if (version === 0) {
          const data = convertBits(decoded.words.slice(1), 5, 8, false)
          if (data.length === 20) {
            type = 'P2WPKH (Native SegWit v0)'
          } else if (data.length === 32) {
            type = 'P2WSH (Native SegWit v0)'
          }
        } else if (version === 1) {
          type = 'P2TR (Taproot)'
        }
      }
      
      return {
        type,
        hash: 'N/A for Bech32',
        checksum: 'N/A for Bech32'
      }
    } else {
      // Legacy address
      const decoded = base58Decode(address)
      const prefix = decoded[0]
      const hash = Array.from(decoded.slice(1, -4)).map(b => b.toString(16).padStart(2, '0')).join('')
      const checksum = Array.from(decoded.slice(-4)).map(b => b.toString(16).padStart(2, '0')).join('')
      
      let type = 'Unknown'
      if (prefix === 0x00) type = 'P2PKH (Legacy)'
      else if (prefix === 0x05) type = 'P2SH (Script Hash)'
      
      return { type, hash, checksum }
    }
  } catch (error) {
    return null
  }
}

// Mini key functions
export async function generateMiniKey(): Promise<string> {
  let miniKey: string
  do {
    const randomBytes = new Uint8Array(29)
    crypto.getRandomValues(randomBytes)
    miniKey = 'S'
    
    const charset = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    for (let i = 0; i < 29; i++) {
      miniKey += charset[randomBytes[i] % charset.length]
    }
  } while (!(await validateMiniKey(miniKey)).valid)
  
  return miniKey
}

export async function validateMiniKey(miniKey: string): Promise<{ valid: boolean; error?: string }> {
  if (!miniKey || typeof miniKey !== 'string') {
    return { valid: false, error: 'Invalid input' }
  }
  
  if (miniKey.length !== 30) {
    return { valid: false, error: 'Invalid: Mini key must be 30 characters long' }
  }
  
  if (!miniKey.startsWith('S')) {
    return { valid: false, error: 'Invalid: First character must be \'S\'' }
  }
  
  const base58Pattern = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/
  if (!base58Pattern.test(miniKey)) {
    return { valid: false, error: 'Invalid: All characters must be in the base58 alphabet' }
  }
  
  // Check mini key validity using SHA256(minikey + '?')[0] == 0
  try {
    const testString = miniKey + '?'
    const testBytes = new TextEncoder().encode(testString)
    const hash = await sha256(testBytes)
    
    if (hash[0] !== 0) {
      return { valid: false, error: 'Invalid: Check failed' }
    }
    
    return { valid: true }
  } catch (error) {
    return { valid: false, error: 'Invalid: Check failed' }
  }
}

export async function miniKeyToPrivateKey(miniKey: string): Promise<string | null> {
  const validation = await validateMiniKey(miniKey)
  if (!validation.valid) return null
  
  try {
    const miniKeyBytes = new TextEncoder().encode(miniKey)
    const hash = await sha256(miniKeyBytes)
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('')
  } catch (error) {
    return null
  }
}

// BIP39 functions (simplified for demo)
const BIP39_WORDLIST = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
  'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
  'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit',
  'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
  'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
  'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter',
  'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger',
  'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
  'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april', 'arcade', 'arch',
  'arctic', 'area', 'arena', 'argue', 'arm', 'armed', 'armor', 'army', 'around', 'arrange',
  'arrest', 'arrive', 'arrow', 'art', 'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset',
  'assist', 'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract', 'auction'
]

export function generateMnemonic(strength: number = 128): string {
  const entropyBytes = new Uint8Array(strength / 8)
  crypto.getRandomValues(entropyBytes)
  
  let entropyBinary = ''
  for (let i = 0; i < entropyBytes.length; i++) {
    entropyBinary += entropyBytes[i].toString(2).padStart(8, '0')
  }
  
  const checksumLength = strength / 32
  const checksum = '0'.repeat(checksumLength)
  
  const totalBinary = entropyBinary + checksum
  
  const words: string[] = []
  for (let i = 0; i < totalBinary.length; i += 11) {
    const wordIndex = parseInt(totalBinary.slice(i, i + 11), 2) % BIP39_WORDLIST.length
    words.push(BIP39_WORDLIST[wordIndex])
  }
  
  return words.join(' ')
}

export function validateMnemonic(mnemonic: string): boolean {
  const words = mnemonic.trim().split(/\s+/)
  const validWordCounts = [12, 15, 18, 21, 24]
  
  if (!validWordCounts.includes(words.length)) {
    return false
  }
  
  return words.every(word => BIP39_WORDLIST.includes(word.toLowerCase()))
}

export async function mnemonicToSeed(mnemonic: string, passphrase: string = ''): Promise<Uint8Array> {
  const mnemonicBytes = new TextEncoder().encode(mnemonic)
  const saltBytes = new TextEncoder().encode('mnemonic' + passphrase)
  
  const combinedBytes = new Uint8Array(mnemonicBytes.length + saltBytes.length)
  combinedBytes.set(mnemonicBytes)
  combinedBytes.set(saltBytes, mnemonicBytes.length)
  
  return await sha256(combinedBytes)
}

export function mnemonicToEntropy(mnemonic: string): string {
  const words = mnemonic.trim().split(/\s+/)
  
  let binaryString = ''
  for (const word of words) {
    const index = BIP39_WORDLIST.indexOf(word.toLowerCase())
    if (index === -1) return ''
    binaryString += index.toString(2).padStart(11, '0')
  }
  
  const entropyLength = (words.length * 11 - words.length / 3) 
  const entropyBinary = binaryString.slice(0, Math.floor(entropyLength))
  
  let hex = ''
  for (let i = 0; i < entropyBinary.length; i += 8) {
    const byte = parseInt(entropyBinary.slice(i, i + 8), 2)
    hex += byte.toString(16).padStart(2, '0')
  }
  
  return hex
}

export async function derivePrivateKey(seed: Uint8Array, path: string): Promise<string> {
  const pathBytes = new TextEncoder().encode(path)
  const combinedBytes = new Uint8Array(seed.length + pathBytes.length)
  combinedBytes.set(seed)
  combinedBytes.set(pathBytes, seed.length)
  
  const hash = await sha256(combinedBytes)
  return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('')
}

export function generateAddressFromPrivateKey(privateKeyHex: string, addressType: string = 'p2pkh'): string {
  const hash = privateKeyHex.slice(0, 40)
  
  switch (addressType) {
    case 'p2pkh':
      return '1' + hash.slice(0, 33)
    case 'p2sh':
      return '3' + hash.slice(0, 33)
    case 'bech32':
      return 'bc1q' + hash.slice(0, 32)
    case 'taproot':
      return 'bc1p' + hash.slice(0, 32)
    default:
      return '1' + hash.slice(0, 33)
  }
}