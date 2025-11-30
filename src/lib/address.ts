import { Buffer } from '@/lib/polyfills'
import { 
  doubleSha256,
  hash160
} from '@/lib/crypto'
import {
  decodeBase58,
  encodeBase58,
} from './base58'
import {
  bech32Encode,
  bech32Decode,
  convertBits,
} from './bech32'

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
  const p2pkhAddress = encodeBase58(p2pkhWithChecksum)
  
  // P2SH Address (Script Hash)
  const p2shPayload = new Uint8Array(21)
  p2shPayload[0] = 0x05 // P2SH prefix
  p2shPayload.set(publicKeyHash, 1)
  const p2shChecksum = await doubleSha256(p2shPayload)
  const p2shWithChecksum = new Uint8Array(25)
  p2shWithChecksum.set(p2shPayload)
  p2shWithChecksum.set(p2shChecksum.slice(0, 4), 21)
  const p2shAddress = encodeBase58(p2shWithChecksum)
  
  // Bech32 Address (SegWit v0)
  const witnessVersion = 0
  const witnessProgram = Array.from(publicKeyHash)
  const bech32Data = convertBits([witnessVersion, ...witnessProgram], 8, 5)
  const bech32Address = bech32Encode('bc', bech32Data)
  
  // Taproot Address (SegWit v1)
  const taprootVersion = 1
  const taprootProgram = Array.from(publicKeyBytes.slice(1, 33)) // x-only pubkey
  const taprootData = convertBits([taprootVersion, ...taprootProgram], 8, 5)
  const taprootAddress = bech32Encode('bc', taprootData)
  
  return {
    p2pkhAddress,
    p2shAddress,
    bech32Address,
    taprootAddress,
    publicKeyHash: publicKeyHashHex
  }
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
        const decoded = decodeBase58(address)
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
      const decoded = decodeBase58(address)
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
