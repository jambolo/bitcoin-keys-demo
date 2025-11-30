import { describe, it, expect } from 'vitest';
import {
  BASE58_ALPHABET,
  decodeBase58,
  encodeBase58,
  decodeBase58Check,
  encodeBase58Check,
} from './base58';

describe('Base58 Encoding/Decoding', () => {
  describe('BASE58_ALPHABET', () => {
    it('should have correct alphabet', () => {
      expect(BASE58_ALPHABET).toBe('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
      expect(BASE58_ALPHABET.length).toBe(58);
    });
  });

  describe('decodeBase58', () => {
    it('should decode valid Base58 string', () => {
      const decoded = decodeBase58('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.length).toBeGreaterThan(0);
    });
  });

  describe('encodeBase58', () => {
    it('should encode bytes to Base58', () => {
      const bytes = new Uint8Array([1, 2, 3, 4, 5]);
      const encoded = encodeBase58(bytes);
      expect(typeof encoded).toBe('string');
      expect(encoded.length).toBeGreaterThan(0);
    });

    it('should round-trip encode/decode', () => {
      const original = new Uint8Array([72, 101, 108, 108, 111]);
      const encoded = encodeBase58(original);
      const decoded = decodeBase58(encoded);
      expect(decoded).toEqual(original);
    });
  });

  describe('decodeBase58Check', () => {
    it('should decode valid Base58Check address', () => {
      const address = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
      const decoded = decodeBase58Check(address);
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded[0]).toBe(0x00); // mainnet P2PKH version
    });

    it('should throw on invalid checksum', () => {
      const invalidAddress = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb'; // changed last char
      expect(() => decodeBase58Check(invalidAddress)).toThrow('Invalid checksum');
    });
  });

  describe('encodeBase58Check', () => {
    it('should encode with checksum', () => {
      const payload = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
      const encoded = encodeBase58Check(payload);
      expect(typeof encoded).toBe('string');
      expect(encoded.length).toBeGreaterThan(0);
    });

    it('should round-trip encode/decode with checksum', () => {
      const original = new Uint8Array([0x00, 0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18]);
      const encoded = encodeBase58Check(original);
      const decoded = decodeBase58Check(encoded);
      expect(decoded).toEqual(original);
    });
  });
});
