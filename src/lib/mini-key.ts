import { sha256 } from '@/lib/crypto'

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
