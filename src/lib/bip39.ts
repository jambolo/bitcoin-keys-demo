import { sha256 } from '@/lib/crypto'

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
