import { describe, it, expect } from 'vitest'
import {
  generateMiniKey,
  validateMiniKey,
  miniKeyToPrivateKey
} from './mini-key'
import { isValidHex } from './keys'

describe('Mini Key', () => {
  // Known mini key test vector
  const knownMiniKey = 'S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy'

  it('should validate known valid mini key', async () => {
    const result = await validateMiniKey(knownMiniKey)
    expect(result.valid).toBe(true)
  })

  it('should reject mini key with wrong length', async () => {
    const result = await validateMiniKey('S6c56bnXQiBjk9mqSYE7ykVQ7NzrR') // 29 chars, not 30
    expect(result.valid).toBe(false)
    expect(result.error).toContain('30 characters')
  })

  it('should reject mini key not starting with S', async () => {
    const result = await validateMiniKey('A6c56bnXQiBjk9mqSYE7ykVQ7NzrRy')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('must be \'S\'')
  })

  it('should reject mini key with invalid characters', async () => {
    const result = await validateMiniKey('S0c56bnXQiBjk9mqSYE7ykVQ7NzrRy') // Contains '0'
    expect(result.valid).toBe(false)
    expect(result.error).toContain('base58')
  })

  it('should convert valid mini key to private key', async () => {
    const privateKeyHex = await miniKeyToPrivateKey(knownMiniKey)
    expect(privateKeyHex).not.toBeNull()
    expect(privateKeyHex).toHaveLength(64)
    expect(isValidHex(privateKeyHex!, 64)).toBe(true)
  })

  it('should return null for invalid mini key', async () => {
    const privateKeyHex = await miniKeyToPrivateKey('invalid')
    expect(privateKeyHex).toBeNull()
  })

  it('should generate valid mini key', async () => {
    const miniKey = await generateMiniKey()
    expect(miniKey).toHaveLength(30)
    expect(miniKey.startsWith('S')).toBe(true)
    
    const validation = await validateMiniKey(miniKey)
    expect(validation.valid).toBe(true)
  })
})
