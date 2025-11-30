import { describe, it, expect } from 'vitest'
import {
  sha256,
  doubleSha256,
  ripemd160,
  hash160,
  generatePublicKey,
} from './crypto'


describe('SHA256', () => {
  it('should compute SHA256 of empty input', async () => {
    const input = new Uint8Array([])
    const result = await sha256(input)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result.length).toBe(32)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  it('should compute SHA256 of known input', async () => {
    const input = new TextEncoder().encode('hello')
    const result = await sha256(input)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
  })

  it('should compute SHA256 of "abc"', async () => {
    const input = new TextEncoder().encode('abc')
    const result = await sha256(input)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
})

describe('Double SHA256', () => {
  it('should compute double SHA256 of empty input', async () => {
    const input = new Uint8Array([])
    const result = await doubleSha256(input)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result.length).toBe(32)
    // Double SHA256 of empty string
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456')
  })

  it('should compute double SHA256 of known input', async () => {
    const input = new TextEncoder().encode('hello')
    const result = await doubleSha256(input)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50')
  })

  it('should be equivalent to SHA256(SHA256(input))', async () => {
    const input = new TextEncoder().encode('test')
    const result1 = await doubleSha256(input)
    const hash1 = await sha256(input)
    const result2 = await sha256(hash1)
    expect(Array.from(result1)).toEqual(Array.from(result2))
  })
})

describe('RIPEMD160', () => {
  it('should compute RIPEMD160 of empty input', async () => {
    const input = new Uint8Array([])
    const result = await ripemd160(input)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result.length).toBe(20)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('9c1185a5c5e9fc54612808977ee8f548b2258d31')
  })

  it('should compute RIPEMD160 of "abc"', async () => {
    const input = new TextEncoder().encode('abc')
    const result = await ripemd160(input)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc')
  })

  it('should compute RIPEMD160 of longer string', async () => {
    const input = new TextEncoder().encode('message digest')
    const result = await ripemd160(input)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('5d0689ef49d2fae572b881b123a85ffa21595f36')
  })
})

describe('hash160', () => {
  it('should compute hash160 (SHA256 + RIPEMD160)', async () => {
    const input = new TextEncoder().encode('test')
    const result = await hash160(input)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result.length).toBe(20)
    
    // Verify it's equivalent to RIPEMD160(SHA256(input))
    const sha = await sha256(input)
    const expected = await ripemd160(sha)
    expect(Array.from(result)).toEqual(Array.from(expected))
  })

  it('should compute hash160 of public key', async () => {
    // Compressed public key for testing
    const pubkeyHex = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    const pubkey = new Uint8Array(pubkeyHex.length / 2)
    for (let i = 0; i < pubkeyHex.length; i += 2) {
      pubkey[i / 2] = parseInt(pubkeyHex.substring(i, i + 2), 16)
    }
    
    const result = await hash160(pubkey)
    expect(result.length).toBe(20)
    const hex = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hex).toBe('751e76e8199196d454941c45d1b3a323f1433bd6')
  })
})

describe('generatePublicKey', () => {
  it('should generate uncompressed public key', async () => {
    const privateKeyHex = '0000000000000000000000000000000000000000000000000000000000000001'
    const result = await generatePublicKey(privateKeyHex, false)
    
    expect(result).toBeTruthy()
    expect(result!.length).toBe(130) // 65 bytes * 2 hex chars
    expect(result!.startsWith('04')).toBe(true) // Uncompressed prefix
  })

  it('should generate compressed public key', async () => {
    const privateKeyHex = '0000000000000000000000000000000000000000000000000000000000000001'
    const result = await generatePublicKey(privateKeyHex, true)
    
    expect(result).toBeTruthy()
    expect(result!.length).toBe(66) // 33 bytes * 2 hex chars
    expect(['02', '03']).toContain(result!.substring(0, 2)) // Compressed prefix
  })

  it('should generate correct public key for known private key', async () => {
    // Private key = 1
    const privateKeyHex = '0000000000000000000000000000000000000000000000000000000000000001'
    const result = await generatePublicKey(privateKeyHex, true)
    
    // Should be the generator point G in compressed form
    expect(result).toBe('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
  })

  it('should throw for invalid private key', async () => {
    await expect(async () => {
      await generatePublicKey('invalid', true)
    }).rejects.toThrow()
  })

  it('should throw for zero private key', async () => {
    const privateKeyHex = '0000000000000000000000000000000000000000000000000000000000000000'
    await expect(async () => {
      await generatePublicKey(privateKeyHex, true)
    }).rejects.toThrow()
  })

  it('should throw for private key >= CURVE_ORDER', async () => {
    // CURVE_ORDER value should be rejected
    const privateKeyHex = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
    await expect(async () => {
      await generatePublicKey(privateKeyHex, true)
    }).rejects.toThrow()
  })

  it('should handle different private keys correctly', async () => {
    const privateKeyHex = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
    const result = await generatePublicKey(privateKeyHex, true)
    
    expect(result).toBeTruthy()
    expect(result!.length).toBe(66)
    expect(['02', '03']).toContain(result!.substring(0, 2))
  })

  it('should produce different public keys for different private keys', async () => {
    const key1 = await generatePublicKey('0000000000000000000000000000000000000000000000000000000000000001', true)
    const key2 = await generatePublicKey('0000000000000000000000000000000000000000000000000000000000000002', true)
    
    expect(key1).not.toBe(key2)
  })
})
