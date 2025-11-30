// Bech32 encoding for SegWit addresses
export const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

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

export function bech32Encode(hrp: string, data: number[]): string {
  const checksum = bech32CreateChecksum(hrp, data)
  const combined = [...data, ...checksum]
  return hrp + '1' + combined.map(d => BECH32_CHARSET[d]).join('')
}

export function bech32Decode(bech32str: string): { prefix: string; words: number[] } | null {
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

export function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean = true): number[] {
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
