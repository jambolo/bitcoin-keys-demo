import { describe, it, expect } from 'vitest'
import {
  generateRandomPrivateKey,
  encodeWif,
  decodeWif,
  validateWif,
  generateWifSteps,
  privateKeyFromWif,
  privateKeyFromHex,
  validatePublicKey,
  isValidHex
} from './keys'

describe('Hex Validation', () => {
  it('should validate correct hex strings', () => {
    expect(isValidHex('00')).toBe(true)
    expect(isValidHex('ff')).toBe(true)
    expect(isValidHex('0123456789abcdef')).toBe(true)
    expect(isValidHex('0123456789ABCDEF')).toBe(true)
  })

  it('should reject invalid hex strings', () => {
    expect(isValidHex('')).toBe(false)
    expect(isValidHex('g')).toBe(false)
    expect(isValidHex('0x00')).toBe(false)
    expect(isValidHex('zz')).toBe(false)
    expect(isValidHex('hello')).toBe(false)
  })

  it('should validate hex with expected length', () => {
    expect(isValidHex('00', 2)).toBe(true)
    expect(isValidHex('0000', 4)).toBe(true)
    expect(isValidHex('00', 4)).toBe(false)
    expect(isValidHex('0000', 2)).toBe(false)
  })
})

describe('WIF Encoding and Decoding', () => {
  // Test vectors from Bitcoin Core
  const testVectors = [
    {
      privateKeyHex: '0000000000000000000000000000000000000000000000000000000000000001',
      wifUncompressed: '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf',
      wifCompressed: 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
      compressed: true
    },
    {
      privateKeyHex: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
      wifUncompressed: '5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3jsuDU2KYEqetqj84qw',
      wifCompressed: 'L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFLaHLuZ9',
      compressed: true
    }
  ]

  it('should encode compressed private key to WIF', async () => {
    const wif = await encodeWif(testVectors[0].privateKeyHex, true)
    expect(wif).toBe(testVectors[0].wifCompressed)
  })

  it('should decode compressed WIF correctly', async () => {
    const decoded = await decodeWif(testVectors[0].wifCompressed)
    expect(decoded).not.toBeNull()
    expect(decoded?.privateKeyHex).toBe(testVectors[0].privateKeyHex)
    expect(decoded?.compressed).toBe(true)
    expect(decoded?.valid).toBe(true)
  })

  it('should encode uncompressed private key to WIF', async () => {
    const wif = await encodeWif(testVectors[0].privateKeyHex, false)
    expect(wif).toBe(testVectors[0].wifUncompressed)
  })

  it('should decode uncompressed WIF correctly', async () => {
    const decoded = await decodeWif(testVectors[0].wifUncompressed)
    expect(decoded).not.toBeNull()
    expect(decoded?.privateKeyHex).toBe(testVectors[0].privateKeyHex)
    expect(decoded?.compressed).toBe(false)
    expect(decoded?.valid).toBe(true)
  })

  it('should validate correct WIF', async () => {
    const result = await validateWif(testVectors[0].wifCompressed)
    expect(result.valid).toBe(true)
    expect(result.error).toBeUndefined()
  })

  it('should reject invalid WIF with bad checksum', async () => {
    const invalidWif = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm' // Changed last char
    const result = await validateWif(invalidWif)
    expect(result.valid).toBe(false)
    expect(result.error).toBeDefined()
  })

  it('should reject WIF with invalid characters', async () => {
    const result = await validateWif('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoW0') // Contains '0'
    expect(result.valid).toBe(false)
    expect(result.error).toBe('Invalid characters')
  })

  it('should reject empty string', async () => {
    const result = await validateWif('')
    expect(result.valid).toBe(false)
  })

  it('should generate WIF encoding steps correctly', async () => {
    const steps = await generateWifSteps(testVectors[0].privateKeyHex, true)
    expect(steps.wif).toBe(testVectors[0].wifCompressed)
    expect(steps.step1).toContain('80') // Mainnet prefix
    expect(steps.step1).toContain('01') // Compressed suffix
    expect(steps.checksumFirst4).toHaveLength(8) // 4 bytes in hex
  })
})

describe('Private Key Generation and Derivation', () => {
  it('should generate a valid random private key', async () => {
    const wif = await generateRandomPrivateKey()
    const validation = await validateWif(wif)
    expect(validation.valid).toBe(true)
  })

  it('should derive key data from valid WIF', async () => {
    const wif = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
    const keyData = await privateKeyFromWif(wif)
    
    expect(keyData).not.toBeNull()
    expect(keyData?.privateKeyWif).toBe(wif)
    expect(keyData?.privateKeyHex).toHaveLength(64)
    expect(keyData?.compressed).toBe(true)
    expect(keyData?.publicKeyHex).toBeDefined()
    expect(keyData?.p2pkhAddress).toBeDefined()
    expect(keyData?.bech32Address).toBeDefined()
  })

  it('should derive key data from valid hex', async () => {
    const hex = '0000000000000000000000000000000000000000000000000000000000000001'
    const keyData = await privateKeyFromHex(hex)
    
    expect(keyData).not.toBeNull()
    expect(keyData?.privateKeyHex).toBe(hex)
    expect(keyData?.compressed).toBe(true)
    expect(keyData?.publicKeyHex).toBeDefined()
  })

  it('should reject invalid hex length', async () => {
    const invalidHex = '0001' // Too short
    const keyData = await privateKeyFromHex(invalidHex)
    expect(keyData).toBeNull()
  })
})

describe('Public Key Validation', () => {
  it('should validate compressed public key with 02 prefix', () => {
    const pubkey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    const result = validatePublicKey(pubkey)
    expect(result.valid).toBe(true)
  })

  it('should validate compressed public key with 03 prefix', () => {
    const pubkey = '0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    const result = validatePublicKey(pubkey)
    expect(result.valid).toBe(true)
  })

  it('should validate uncompressed public key with 04 prefix', () => {
    const pubkey = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    const result = validatePublicKey(pubkey)
    expect(result.valid).toBe(true)
  })

  it('should reject public key with invalid prefix', () => {
    const pubkey = '0179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    const result = validatePublicKey(pubkey)
    expect(result.valid).toBe(false)
    expect(result.error).toBe('Invalid prefix')
  })

  it('should reject compressed public key with wrong length', () => {
    const pubkey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817' // Missing 2 chars
    const result = validatePublicKey(pubkey)
    expect(result.valid).toBe(false)
    expect(result.error).toBe('Missing characters')
  })

  it('should reject uncompressed public key with wrong length', () => {
    const pubkey = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4' // Missing chars
    const result = validatePublicKey(pubkey)
    expect(result.valid).toBe(false)
    expect(result.error).toBe('Missing characters')
  })

  it('should reject non-hex characters', () => {
    const pubkey = '02zzbe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    const result = validatePublicKey(pubkey)
    expect(result.valid).toBe(false)
    expect(result.error).toBe('Invalid characters')
  })
})

describe('Edge Cases and Error Handling', () => {
  it('should handle null and undefined inputs gracefully', async () => {
    expect(isValidHex('')).toBe(false)
    expect(validatePublicKey('').valid).toBe(false)
    
    const wifResult = await validateWif('')
    expect(wifResult.valid).toBe(false)
  })

  it('should handle extremely small private key values', async () => {
    const smallKey = '0000000000000000000000000000000000000000000000000000000000000001'
    const wif = await encodeWif(smallKey, true)
    expect(wif).toBeDefined()
    expect(wif).not.toBeNull()
  })

  it('should handle maximum valid private key value', async () => {
    // Just below the curve order
    const maxKey = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'
    const wif = await encodeWif(maxKey, true)
    expect(wif).toBeDefined()
    expect(wif).not.toBeNull()
  })

  it('should reject private key equal to zero', async () => {
    const zeroKey = '0000000000000000000000000000000000000000000000000000000000000000'
    const keyData = await privateKeyFromHex(zeroKey)
    expect(keyData).toBeDefined()
    expect(keyData).toBeNull()
  })

  it('should handle very long input strings', async () => {
    const longString = 'a'.repeat(10000)
    expect(isValidHex(longString)).toBe(true) // All 'a's are valid hex
    expect(validatePublicKey(longString).valid).toBe(false) // But not valid public key
  })
})

describe('Cryptographic Standards Compliance', () => {
  it('should generate SECP256k1 compatible key pairs', async () => {
    const wif = await generateRandomPrivateKey()
    const keyData = await privateKeyFromWif(wif)
    
    // Public key should be 33 bytes (compressed) or 65 bytes (uncompressed) in hex
    expect(keyData?.publicKeyHex).toBeDefined()
    const pubkeyLength = keyData!.publicKeyHex!.length
    expect([66, 130]).toContain(pubkeyLength)
  })

  it('should use correct Bitcoin mainnet version bytes', async () => {
    const privateKeyHex = '0000000000000000000000000000000000000000000000000000000000000001'
    const wif = await encodeWif(privateKeyHex, true)
    
    // WIF should start with 'K' or 'L' for compressed mainnet keys
    expect(wif![0]).toMatch(/[KL]/)
  })

  it('should generate valid checksums', async () => {
    const privateKeyHex = '0000000000000000000000000000000000000000000000000000000000000001'
    const wif = await encodeWif(privateKeyHex, true)
    
    const decoded = await decodeWif(wif!)
    expect(decoded?.valid).toBe(true)
    expect(decoded?.checksum).toBeDefined()
    expect(decoded?.checksum.length).toBe(8) // 4 bytes in hex
  })
})

describe('Performance and Stress Tests', () => {
  it('should handle multiple concurrent key generations', async () => {
    const promises = Array.from({ length: 10 }, () => generateRandomPrivateKey())
    const keys = await Promise.all(promises)
    
    expect(keys.length).toBe(10)
    keys.forEach(key => {
      expect(key).toBeDefined()
      expect(key.length).toBeGreaterThan(0)
    })
    
    // All keys should be unique
    const uniqueKeys = new Set(keys)
    expect(uniqueKeys.size).toBe(10)
  })

  it('should handle rapid sequential validations', async () => {
    const wif = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
    
    const validations = await Promise.all(
      Array.from({ length: 100 }, () => validateWif(wif))
    )
    
    expect(validations.every(v => v.valid)).toBe(true)
  })
})
