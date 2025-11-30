import bs58 from 'bs58';

// Base58 Encoding/Decoding

export const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function decodeBase58(input: string): Uint8Array {
  return bs58.decode(input);
}

export function encodeBase58(bytes: Uint8Array): string {
  return bs58.encode(bytes);
}

export function decodeBase58Check(input: string): Uint8Array {
  const decoded = decodeBase58(input);
  const payload = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);
  
  const hash1 = crypto.subtle.digestSync('SHA-256', payload);
  const hash2 = crypto.subtle.digestSync('SHA-256', hash1);
  const expectedChecksum = new Uint8Array(hash2.slice(0, 4));
  
  if (!arraysEqual(checksum, expectedChecksum)) {
    throw new Error('Invalid checksum');
  }
  
  return payload;
}

export function encodeBase58Check(payload: Uint8Array): string {
  const hash1 = crypto.subtle.digestSync('SHA-256', payload);
  const hash2 = crypto.subtle.digestSync('SHA-256', hash1);
  const checksum = new Uint8Array(hash2.slice(0, 4));
  
  const combined = new Uint8Array(payload.length + 4);
  combined.set(payload);
  combined.set(checksum, payload.length);
  
  return encodeBase58(combined);
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
