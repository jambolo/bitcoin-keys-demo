// Type definitions for Bitcoin key data
export interface BitcoinKeyData {
  privateKeyWif?: string
  privateKeyHex?: string
  compressed?: boolean
  publicKeyHex?: string
  publicKeyHash?: string
  p2pkhAddress?: string
  p2shAddress?: string
  bech32Address?: string
  taprootAddress?: string
}
