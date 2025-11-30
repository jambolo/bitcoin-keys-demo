import { describe, it, expect } from 'vitest'
import {
  generateRandomPrivateKey,
  validateWif,
  privateKeyFromWif,
  validatePublicKey,
  isValidHex,
  privateKeyFromHex
} from './keys'
import {
  generateAddresses,
  validateBitcoinAddress
} from './address'
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  derivePrivateKey
} from './bip39'

describe('Integration Tests', () => {
  it('should complete full key generation flow from private key to addresses', async () => {
    // Generate random private key
    const wif = await generateRandomPrivateKey()
    expect(wif).toBeDefined()
    
    // Validate WIF
    const validation = await validateWif(wif)
    expect(validation.valid).toBe(true)
    
    // Derive full key data
    const keyData = await privateKeyFromWif(wif)
    expect(keyData).not.toBeNull()
    expect(keyData?.privateKeyHex).toBeDefined()
    expect(keyData?.publicKeyHex).toBeDefined()
    
    // Validate public key
    const pubkeyValidation = validatePublicKey(keyData!.publicKeyHex!)
    expect(pubkeyValidation.valid).toBe(true)
    
    // Validate generated addresses
    const p2pkhValid = await validateBitcoinAddress(keyData!.p2pkhAddress!)
    expect(p2pkhValid.valid).toBe(true)
    
    const bech32Valid = await validateBitcoinAddress(keyData!.bech32Address!)
    expect(bech32Valid.valid).toBe(true)
  })

  it('should complete full mnemonic to address flow', async () => {
    // Generate mnemonic
    const mnemonic = generateMnemonic(128)
    expect(validateMnemonic(mnemonic)).toBe(true)
    
    // Convert to seed
    const seed = await mnemonicToSeed(mnemonic, 'test passphrase')
    expect(seed).toBeDefined()
    
    // Derive private key
    const privateKey = await derivePrivateKey(seed, "m/44'/0'/0'/0/0")
    expect(isValidHex(privateKey, 64)).toBe(true)
    
    // Generate addresses
    const keyData = await privateKeyFromHex(privateKey)
    expect(keyData).not.toBeNull()
    expect(keyData?.p2pkhAddress).toBeDefined()
  })

  it('should maintain consistency across multiple operations', async () => {
    const originalHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    
    // Generate addresses from hex private key
    const keyData = await privateKeyFromHex(originalHex)
    expect(keyData).not.toBeNull()
    expect(keyData?.privateKeyHex).toBe(originalHex)
    
    // Validate all generated addresses
    if (keyData?.p2pkhAddress) {
      const p2pkhValid = await validateBitcoinAddress(keyData.p2pkhAddress)
      expect(p2pkhValid.valid).toBe(true)
    }
    
    if (keyData?.bech32Address) {
      const bech32Valid = await validateBitcoinAddress(keyData.bech32Address)
      expect(bech32Valid.valid).toBe(true)
    }
  })
})
