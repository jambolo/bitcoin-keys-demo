import * as bitcoin from 'bitcoinjs-lib'
import * as tinysecp256k1 from 'tiny-s

const ECPair = ECPairFactory(t

  mnemonic: string
  expectedPrivateKey: string


export const BIP86_TE
  mnemonic: string
  derivationPath: string
  expectedPrivateKey: string
  expectedXOnlyPubkey: string
  expectedTaprootAddress: string
}

// BIP-86 test vectors from the specification
export const BIP86_TEST_VECTORS: BIP86TestVector[] = [
  {
    derivationPath: "m/86'/0'/0'/0/1",
    expectedXOnlyPubkey: "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
  }

  privateKey: string
  taprootAddress: string
  er

 * Derives a BIP-86 taproot address from 
export function deriveBIP86Address(mnemonic: string, derivationPath: string): BIP86DerivationResult {
  
    // Step 1: Convert mnemonic to seed
    
    const root = bitcoin.bip32.fromSeed(seed)
   
 

    
    
    const pubkey = ch
  taprootAddress: string
  isValid: boolean
  errors: string[]
}

/**
 * Derives a BIP-86 taproot address from a mnemonic and derivation path
 */
export function deriveBIP86Address(mnemonic: string, derivationPath: string): BIP86DerivationResult {
  const errors: string[] = []
  
  try {
    // Step 1: Convert mnemonic to seed
    const seed = bip39.mnemonicToSeedSync(mnemonic)
    
    // Step 2: Create master key from seed
    const root = bitcoin.bip32.fromSeed(seed)
    
    // Step 3: Derive key at specified path
    const child = root.derivePath(derivationPath)
    
    if (!child.privateKey) {
      throw new Error('Failed to derive private key')
    }
    
    const privateKey = child.privateKey.toString('hex')
    
    // Step 4: Get x-only public key (32 bytes, remove prefix)
    const pubkey = child.publicKey
    let xOnlyPubkey: Buffer
    
    if (pubkey.length === 33) {
      // Compressed key - remove prefix byte
      xOnlyPubkey = pubkey.subarray(1)
    } else if (pubkey.length === 65) {
      // Uncompressed key - take x coordinate (bytes 1-32)
      xOnlyPubkey = pubkey.subarray(1, 33)
    } else {
      throw new Error(`Invalid public key length: ${pubkey.length}`)
    }
    
    // Step 5: Create BIP-86 taproot address
    const p2tr = bitcoin.payments.p2tr({
      internalPubkey: xOnlyPubkey,
      network: bitcoin.networks.bitcoin
    })
    
    if (!p2tr.address) {
      throw new Error('Failed to generate taproot address')
    }
    
    return {
      privateKey,
      xOnlyPubkey: xOnlyPubkey.toString('hex'),
      taprootAddress: p2tr.address,
      isValid: true,
      errors: []
    }
    
  } catch (error) {
    errors.push(`Derivation failed: ${error instanceof Error ? error.message : String(error)}`)
    return {
      privateKey: '',
      xOnlyPubkey: '',
      taprootAddress: '',
      isValid: false,
      errors
    }
  }
}

/**
 * Verifies our BIP-86 implementation against known test vectors
 */
export function verifyBIP86Implementation(): {
  passed: number
  failed: number
  total: number
  results: Array<{
    testVector: BIP86TestVector
    result: BIP86DerivationResult
    passed: boolean
    issues: string[]
  }>
} {
  const results = BIP86_TEST_VECTORS.map(testVector => {
    const result = deriveBIP86Address(testVector.mnemonic, testVector.derivationPath)
    const issues: string[] = []
    
    // Compare private key
    if (result.privateKey !== testVector.expectedPrivateKey) {
      issues.push(`Private key mismatch: expected ${testVector.expectedPrivateKey}, got ${result.privateKey}`)
    }
    
    // Compare x-only public key
    if (result.xOnlyPubkey !== testVector.expectedXOnlyPubkey) {
      issues.push(`X-only pubkey mismatch: expected ${testVector.expectedXOnlyPubkey}, got ${result.xOnlyPubkey}`)
    }
    
    // Compare taproot address
    if (result.taprootAddress !== testVector.expectedTaprootAddress) {
      issues.push(`Taproot address mismatch: expected ${testVector.expectedTaprootAddress}, got ${result.taprootAddress}`)
    }
    
    // Check for any derivation errors
    if (!result.isValid) {
      issues.push(...result.errors)
    }
    
    return {
      testVector,
      result,
      passed: issues.length === 0 && result.isValid,
      issues
    }
  })
  
  const passed = results.filter(r => r.passed).length
  const failed = results.filter(r => !r.passed).length
  
      'Cro
    externa
      elect
    }
}
/**
 

  c
    score: `${verification.passed}/${verification.total
    recommendations: [] as string[]
  
    audit.recomme
    audit.recommendations.push('V
  }
  return audit













































