import { bech32Encode, bech32Decode, convertBits } from './bech32'

// Simple manual tests (adapt as needed)
function assertEqual(a: any, b: any, msg: string) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(`Assertion failed: ${msg}\nExpected: ${JSON.stringify(b)}\nGot: ${JSON.stringify(a)}`)
  }
}

// Test vectors from BIP173
const hrp = 'bc'
const data = [0, 14, 20, 15, 0, 13, 10, 2, 7, 0, 3, 19, 5, 8, 9, 23, 1, 21, 11, 4, 6, 17, 12, 16, 18]
const encoded = bech32Encode(hrp, data)
const decoded = bech32Decode(encoded)

assertEqual(typeof encoded, 'string', 'bech32Encode returns string')
assertEqual(decoded && decoded.prefix, hrp, 'bech32Decode returns correct prefix')
assertEqual(decoded && decoded.words.length, data.length, 'bech32Decode returns correct word length')

// convertBits roundtrip
const bytes = [0, 255, 16, 128, 64]
const bits5 = convertBits(bytes, 8, 5)
const bytesBack = convertBits(bits5, 5, 8, false)
assertEqual(bytesBack, bytes, 'convertBits roundtrip')

console.log('bech32 tests passed')
