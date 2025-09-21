// Import polyfills first
import '@/lib/polyfills'
import { Buffer } from 'buffer'
import * as bitcoin from 'bitcoinjs-lib'

import { useState, useEffect } from 'react'
import { useKV } from '@github/spark/hooks'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Copy, Shuffle, ArrowRight } from '@phosphor-icons/react'
import { 
  generateRandomPrivateKey, 
  privateKeyFromWif,
  privateKeyFromHex,
  validateBitcoinAddress,
  decodeAddress,
  BitcoinKeyData,
  isValidHex
} from '@/lib/bitcoin'

export function AddressPage() {
  // Persistent inputs using useKV
  const [wifInput, setWifInput] = useKV('address-wif-input', '')
  const [hexInput, setHexInput] = useKV('address-hex-input', '')
  const [pubkeyInput, setPubkeyInput] = useKV('address-pubkey-input', '')
  const [hashInput, setHashInput] = useKV('address-hash-input', '')
  const [addressInput, setAddressInput] = useKV('address-decode-input', '')
  const [validationInput, setValidationInput] = useKV('address-validation-input', '')

  const [derivedData, setDerivedData] = useState<BitcoinKeyData | null>(null)
  const [decodedAddress, setDecodedAddress] = useState<any>(null)
  const [validation, setValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })

  // Handle derivation inputs
  useEffect(() => {
    let data: BitcoinKeyData | null = null

    if (wifInput) {
      data = privateKeyFromWif(wifInput)
    } else if (hexInput && isValidHex(hexInput, 64)) {
      data = privateKeyFromHex(hexInput)
    } else if (pubkeyInput && isValidHex(pubkeyInput)) {
      // Generate real addresses from public key
      try {
        const pubkeyBuffer = Buffer.from(pubkeyInput, 'hex')
        const hash160Buffer = bitcoin.crypto.hash160(pubkeyBuffer)
        const publicKeyHash = Buffer.from(hash160Buffer).toString('hex')
        
        const p2pkh = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer })
        const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer })
        const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh })
        
        let taprootAddress = 'N/A'
        try {
          if (pubkeyBuffer.length === 33) {
            const p2tr = bitcoin.payments.p2tr({ pubkey: pubkeyBuffer.subarray(1) })
            taprootAddress = p2tr.address || 'N/A'
          }
        } catch {
          // Taproot generation failed
        }
        
        data = {
          publicKeyHex: pubkeyInput,
          publicKeyHash,
          p2pkhAddress: p2pkh.address || 'N/A',
          p2shAddress: p2sh.address || 'N/A',
          bech32Address: p2wpkh.address || 'N/A',
          taprootAddress
        }
      } catch {
        // Invalid public key
        data = null
      }
    } else if (hashInput && isValidHex(hashInput, 40)) {
      // Generate addresses from hash160
      try {
        const hashBuffer = Buffer.from(hashInput, 'hex')
        
        const p2pkh = bitcoin.payments.p2pkh({ hash: hashBuffer })
        const p2wpkh = bitcoin.payments.p2wpkh({ hash: hashBuffer })
        const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh })
        
        data = {
          publicKeyHash: hashInput,
          p2pkhAddress: p2pkh.address || 'N/A',
          p2shAddress: p2sh.address || 'N/A',
          bech32Address: p2wpkh.address || 'N/A',
          taprootAddress: 'N/A' // Cannot derive taproot from hash160 alone
        }
      } catch {
        // Invalid hash
        data = null
      }
    }

    setDerivedData(data)
  }, [wifInput, hexInput, pubkeyInput, hashInput])

  // Handle address decoding
  useEffect(() => {
    if (addressInput) {
      const decoded = decodeAddress(addressInput)
      setDecodedAddress(decoded)
    } else {
      setDecodedAddress(null)
    }
  }, [addressInput])

  // Handle validation
  useEffect(() => {
    if (validationInput) {
      const result = validateBitcoinAddress(validationInput)
      setValidation(result)
    } else {
      setValidation({ valid: false })
    }
  }, [validationInput])

  const generateRandom = () => {
    const randomWif = generateRandomPrivateKey()
    setWifInput(randomWif)
    setHexInput('')
    setPubkeyInput('')
    setHashInput('')
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const clearInputs = () => {
    setWifInput('')
    setHexInput('')
    setPubkeyInput('')
    setHashInput('')
  }

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold mb-2">Address</h2>
        <p className="text-muted-foreground">
          Generate Bitcoin addresses from keys and decode existing addresses.
        </p>
      </div>

      {/* Derivation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            Address Derivation
          </CardTitle>
          <CardDescription>
            Generate Bitcoin addresses from private keys, public keys, or hashes
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <Tabs defaultValue="wif" className="w-full">
            <TabsList className="grid grid-cols-4 w-full">
              <TabsTrigger value="wif">WIF</TabsTrigger>
              <TabsTrigger value="hex">Private Key</TabsTrigger>
              <TabsTrigger value="pubkey">Public Key</TabsTrigger>
              <TabsTrigger value="hash">Hash</TabsTrigger>
            </TabsList>

            <TabsContent value="wif" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="wif-derivation">Private Key (WIF)</Label>
                <div className="flex gap-2">
                  <Input
                    id="wif-derivation"
                    value={wifInput}
                    onChange={(e) => setWifInput(e.target.value)}
                    placeholder="Enter WIF format private key"
                    className="font-mono text-sm"
                  />
                  <Button variant="outline" size="icon" onClick={generateRandom} title="Generate Random">
                    <Shuffle size={16} />
                  </Button>
                  <Button variant="outline" onClick={clearInputs}>Clear</Button>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="hex" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="hex-derivation">Private Key (Hex)</Label>
                <Input
                  id="hex-derivation"
                  value={hexInput}
                  onChange={(e) => setHexInput(e.target.value)}
                  placeholder="64 character hexadecimal private key"
                  className="font-mono text-sm"
                />
              </div>
            </TabsContent>

            <TabsContent value="pubkey" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="pubkey-derivation">Public Key (Hex)</Label>
                <Input
                  id="pubkey-derivation"
                  value={pubkeyInput}
                  onChange={(e) => setPubkeyInput(e.target.value)}
                  placeholder="66 or 130 character hexadecimal public key"
                  className="font-mono text-sm"
                />
              </div>
            </TabsContent>

            <TabsContent value="hash" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="hash-derivation">Public Key Hash (Hex)</Label>
                <Input
                  id="hash-derivation"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="40 character hexadecimal hash"
                  className="font-mono text-sm"
                />
              </div>
            </TabsContent>
          </Tabs>

          {derivedData && (
            <div className="space-y-6">
              <Separator />
              
              {/* Key Chain */}
              <div className="space-y-4">
                <h4 className="font-semibold text-lg">Derived Key Chain</h4>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {derivedData.privateKeyWif && (
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Private Key (WIF)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-sm break-all">
                          {derivedData.privateKeyWif}
                        </code>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.privateKeyWif || '')} title="Copy">
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                  )}

                  {derivedData.privateKeyHex && (
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Private Key (Hex)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-sm break-all">
                          {derivedData.privateKeyHex}
                        </code>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.privateKeyHex || '')} title="Copy">
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                  )}

                  {derivedData.compressed !== undefined && (
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Compression</Label>
                      <div className="flex items-center gap-2">
                        <Badge variant={derivedData.compressed ? "default" : "secondary"}>
                          {derivedData.compressed ? 'Compressed' : 'Uncompressed'}
                        </Badge>
                      </div>
                    </div>
                  )}

                  {derivedData.publicKeyHex && (
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Public Key</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-sm break-all">
                          {derivedData.publicKeyHex}
                        </code>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.publicKeyHex || '')} title="Copy">
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                  )}

                  {derivedData.publicKeyHash && (
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Public Key Hash</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-sm break-all">
                          {derivedData.publicKeyHash}
                        </code>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.publicKeyHash || '')} title="Copy">
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <Separator />

              {/* Addresses */}
              <div className="space-y-4">
                <h4 className="font-semibold text-lg">Generated Addresses</h4>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">P2PKH (Legacy)</Label>
                    <div className="flex gap-2">
                      <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                        {derivedData.p2pkhAddress}
                      </code>
                      <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.p2pkhAddress || '')} title="Copy">
                        <Copy size={16} />
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Starts with '1' - Pay to Public Key Hash</div>
                  </div>

                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">P2SH (Script Hash)</Label>
                    <div className="flex gap-2">
                      <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                        {derivedData.p2shAddress}
                      </code>
                      <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.p2shAddress || '')} title="Copy">
                        <Copy size={16} />
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Starts with '3' - Pay to Script Hash</div>
                  </div>

                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Bech32 (SegWit)</Label>
                    <div className="flex gap-2">
                      <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                        {derivedData.bech32Address}
                      </code>
                      <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.bech32Address || '')} title="Copy">
                        <Copy size={16} />
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Starts with 'bc1q' - Native SegWit</div>
                  </div>

                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Taproot (P2TR)</Label>
                    <div className="flex gap-2">
                      <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                        {derivedData.taprootAddress}
                      </code>
                      <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.taprootAddress || '')} title="Copy">
                        <Copy size={16} />
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Starts with 'bc1p' - Pay to Taproot</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Decoding Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            Address Decoding
          </CardTitle>
          <CardDescription>
            Decode Bitcoin addresses (Legacy, SegWit, and Taproot) to see their components
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="address-decode">Bitcoin Address</Label>
            <Input
              id="address-decode"
              value={addressInput}
              onChange={(e) => setAddressInput(e.target.value)}
              placeholder="Enter Bitcoin address (1..., 3..., bc1q..., bc1p...)"
              className="font-mono text-sm"
            />
          </div>

          <div className="p-3 bg-muted/50 rounded-lg">
            <Label className="text-xs uppercase tracking-wide text-muted-foreground mb-2 block">Example Addresses</Label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-muted-foreground">Legacy P2PKH:</span>
                <button 
                  className="block font-mono text-blue-600 hover:text-blue-800 break-all"
                  onClick={() => setAddressInput('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')}
                >
                  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
                </button>
              </div>
              <div>
                <span className="text-muted-foreground">Legacy P2SH:</span>
                <button 
                  className="block font-mono text-blue-600 hover:text-blue-800 break-all"
                  onClick={() => setAddressInput('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')}
                >
                  3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
                </button>
              </div>
              <div>
                <span className="text-muted-foreground">SegWit v0:</span>
                <button 
                  className="block font-mono text-blue-600 hover:text-blue-800 break-all"
                  onClick={() => setAddressInput('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')}
                >
                  bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
                </button>
              </div>
              <div>
                <span className="text-muted-foreground">Taproot:</span>
                <button 
                  className="block font-mono text-blue-600 hover:text-blue-800 break-all"
                  onClick={() => setAddressInput('bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297')}
                >
                  bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297
                </button>
              </div>
            </div>
          </div>

          {decodedAddress && (
            <div className="space-y-4">
              <Separator />
              <div className="space-y-4">
                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Address Type</Label>
                  <Badge className="text-sm">{decodedAddress.type}</Badge>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">
                      {decodedAddress.witnessVersion !== undefined ? 'Witness Program' : 'Public Key Hash'}
                    </Label>
                    <code className="block p-2 bg-muted rounded font-mono text-sm break-all">
                      {decodedAddress.hash}
                    </code>
                  </div>
                  
                  {decodedAddress.checksum && (
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Checksum</Label>
                      <code className="block p-2 bg-muted rounded font-mono text-sm break-all">
                        {decodedAddress.checksum}
                      </code>
                    </div>
                  )}
                  
                  {decodedAddress.witnessVersion !== undefined && (
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Witness Version</Label>
                      <Badge variant="secondary">{decodedAddress.witnessVersion}</Badge>
                    </div>
                  )}
                </div>
                
                {decodedAddress.witnessVersion !== undefined && (
                  <div className="p-4 bg-accent/10 rounded-lg border border-accent/20">
                    <h5 className="font-medium text-sm mb-2">SegWit Address Details</h5>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Format:</span>
                        <span>Bech32{decodedAddress.witnessVersion === 1 ? 'm' : ''}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Program Length:</span>
                        <span>{decodedAddress.hash.length / 2} bytes</span>
                      </div>
                      {decodedAddress.witnessVersion === 0 && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Script Type:</span>
                          <span>{decodedAddress.hash.length === 40 ? 'P2WPKH' : 'P2WSH'}</span>
                        </div>
                      )}
                      {decodedAddress.witnessVersion === 1 && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Script Type:</span>
                          <span>Pay-to-Taproot</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Validation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            Address Validation
          </CardTitle>
          <CardDescription>
            Validate any string as a potential Bitcoin address
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="address-validation">String to Validate</Label>
            <Input
              id="address-validation"
              value={validationInput}
              onChange={(e) => setValidationInput(e.target.value)}
              placeholder="Enter any string to validate as Bitcoin address"
              className="font-mono text-sm"
            />
          </div>

          {validationInput && (
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wide text-muted-foreground">Validation Result</Label>
              <div className="flex items-center gap-2">
                <Badge variant={validation.valid ? "default" : "destructive"}>
                  {validation.valid ? 'Valid' : 'Invalid'}
                </Badge>
                {validation.error && (
                  <span className="text-sm text-destructive">{validation.error}</span>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}