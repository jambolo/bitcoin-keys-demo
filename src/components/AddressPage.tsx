import { useState, useEffect } from 'react'
import { useKV } from '@github/spark/hooks'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Copy, Shuffle, ArrowRight } from '@phosphor-icons/react'
import { 
  generateRandomPrivateKey,
  privateKeyFromWif,
  privateKeyFromHex,
  validateBitcoinAddress,
  decodeAddress,
  BitcoinKeyData,
  isValidHex,
  generateAddresses,
  doubleSha256,
  base58Encode
} from '@/lib/bitcoin-lite'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

export function AddressPage() {
  // Persistent inputs using useKV
  const [wifInput, setWifInput] = useKV('address-wif-input', '')
  const [hexInput, setHexInput] = useKV('address-hex-input', '')
  const [pubkeyInput, setPubkeyInput] = useKV('address-pubkey-input', '')
  const [hashInput, setHashInput] = useKV('address-hash-input', '')
  const [addressInput, setAddressInput] = useKV('address-decode-input', '')
  const [validationInput, setValidationInput] = useKV('address-validation-input', '')

  // Derived data state
  const [derivedData, setDerivedData] = useState<BitcoinKeyData | null>(null)
  const [decodedAddress, setDecodedAddress] = useState<any>(null)
  const [validationResult, setValidationResult] = useState<{ isValid: boolean; error?: string } | null>(null)

  // Shared state - get taproot address from other pages if available
  const [sharedTaprootAddress] = useKV('shared-taproot-address', '')

  // Auto-populate validation input with shared taproot address
  useEffect(() => {
    if (sharedTaprootAddress && sharedTaprootAddress !== 'N/A' && !validationInput) {
      setValidationInput(sharedTaprootAddress)
    }
  }, [sharedTaprootAddress, validationInput, setValidationInput])

  // Generate random key
  const handleRandomKey = async () => {
    const randomWif = await generateRandomPrivateKey()
    setWifInput(randomWif)
    setHexInput('')
    setPubkeyInput('')
    setHashInput('')
  }

  // Derive all data from any valid input
  useEffect(() => {
    const processInputs = async () => {
      let data: BitcoinKeyData | null = null

      // Try WIF first
      if (wifInput) {
        data = await privateKeyFromWif(wifInput)
        if (data) {
          setHexInput(data.privateKeyHex || '')
          setPubkeyInput(data.publicKeyHex || '')
          setHashInput(data.publicKeyHash || '')
        }
      }
      // Try hex private key
      else if (hexInput && isValidHex(hexInput, 64)) {
        data = await privateKeyFromHex(hexInput)
        if (data) {
          setWifInput(data.privateKeyWif || '')
          setPubkeyInput(data.publicKeyHex || '')
          setHashInput(data.publicKeyHash || '')
        }
      }
      // Try public key
      else if (pubkeyInput && isValidHex(pubkeyInput)) {
        if (pubkeyInput.length === 66 || pubkeyInput.length === 130) {
          try {
            const addresses = await generateAddresses(pubkeyInput)
            data = {
              publicKeyHex: pubkeyInput,
              publicKeyHash: addresses.publicKeyHash,
              p2pkhAddress: addresses.p2pkhAddress,
              p2shAddress: addresses.p2shAddress,
              bech32Address: addresses.bech32Address,
              taprootAddress: addresses.taprootAddress
            }
            setHashInput(addresses.publicKeyHash)
          } catch (error) {
            data = {
              publicKeyHex: pubkeyInput,
              p2pkhAddress: 'Error generating',
              p2shAddress: 'Error generating',
              bech32Address: 'Error generating',
              taprootAddress: 'Error generating'
            }
          }
        }
      }
      // Try public key hash
      else if (hashInput && isValidHex(hashInput, 40)) {
        try {
          // Generate addresses from hash manually
          const hash = new Uint8Array(20)
          for (let i = 0; i < 40; i += 2) {
            hash[i / 2] = parseInt(hashInput.substring(i, i + 2), 16)
          }
          
          // Generate P2PKH address
          const p2pkhPayload = new Uint8Array(21)
          p2pkhPayload[0] = 0x00
          p2pkhPayload.set(hash, 1)
          const p2pkhChecksum = await doubleSha256(p2pkhPayload)
          const p2pkhWithChecksum = new Uint8Array(25)
          p2pkhWithChecksum.set(p2pkhPayload)
          p2pkhWithChecksum.set(p2pkhChecksum.slice(0, 4), 21)
          const p2pkhAddress = base58Encode(p2pkhWithChecksum)
          
          // Generate P2SH address
          const p2shPayload = new Uint8Array(21)
          p2shPayload[0] = 0x05
          p2shPayload.set(hash, 1)
          const p2shChecksum = await doubleSha256(p2shPayload)
          const p2shWithChecksum = new Uint8Array(25)
          p2shWithChecksum.set(p2shPayload)
          p2shWithChecksum.set(p2shChecksum.slice(0, 4), 21)
          const p2shAddress = base58Encode(p2shWithChecksum)
          
          data = {
            publicKeyHash: hashInput,
            p2pkhAddress,
            p2shAddress,
            bech32Address: 'N/A (requires public key)',
            taprootAddress: 'N/A (requires public key)'
          }
        } catch (error) {
          data = {
            publicKeyHash: hashInput,
            p2pkhAddress: 'Error generating',
            p2shAddress: 'Error generating',
            bech32Address: 'N/A',
            taprootAddress: 'N/A'
          }
        }
      }

      setDerivedData(data)

      // Share taproot address with other components
      if (data?.taprootAddress && data.taprootAddress !== 'N/A' && !data.taprootAddress.includes('Error')) {
        setValidationInput(data.taprootAddress)
      }
    }
    
    processInputs()
  }, [wifInput, hexInput, pubkeyInput, hashInput])

  // Decode address
  useEffect(() => {
    if (addressInput) {
      try {
        const decoded = decodeAddress(addressInput)
        setDecodedAddress(decoded)
      } catch (error) {
        setDecodedAddress(null)
      }
    } else {
      setDecodedAddress(null)
    }
  }, [addressInput])

  // Validate address
  useEffect(() => {
    if (validationInput) {
      const result = validateBitcoinAddress(validationInput)
      setValidationResult({ isValid: result.valid, error: result.error })
    } else {
      setValidationResult(null)
    }
  }, [validationInput])

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-6">
      {/* Address Derivation */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Address Derivation
            <Button
              variant="outline"
              size="sm"
              onClick={handleRandomKey}
              className="ml-auto"
            >
              <Shuffle size={16} className="mr-1" />
              Random
            </Button>
          </CardTitle>
          <CardDescription>
            Generate Bitcoin addresses from private keys, public keys, or public key hashes
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="wif-input">Private Key (WIF)</Label>
              <Input
                id="wif-input"
                value={wifInput}
                onChange={(e) => setWifInput(e.target.value)}
                placeholder="Enter WIF private key..."
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="hex-input">Private Key (Hex)</Label>
              <Input
                id="hex-input"
                value={hexInput}
                onChange={(e) => setHexInput(e.target.value)}
                placeholder="Enter hex private key..."
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="pubkey-input">Public Key (Hex)</Label>
              <Input
                id="pubkey-input"
                value={pubkeyInput}
                onChange={(e) => setPubkeyInput(e.target.value)}
                placeholder="Enter public key..."
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="hash-input">Derived Public Key Hash (Hex)</Label>
              <Input
                id="hash-input"
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                placeholder="Enter public key hash..."
                className="font-mono text-xs"
              />
            </div>
          </div>

          {derivedData && (
            <>
              <Separator />
              <div className="space-y-4">
                <h4 className="text-sm font-medium">Generated Addresses</h4>
                <div className="grid gap-4">
                  {derivedData.p2pkhAddress && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label className="text-xs text-muted-foreground">P2PKH (Legacy)</Label>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(derivedData.p2pkhAddress!)}
                        >
                          <Copy size={14} />
                        </Button>
                      </div>
                      <div className="flex gap-2">
                        <Input
                          value={derivedData.p2pkhAddress}
                          readOnly
                          className="font-mono text-xs"
                        />
                        <QRCodeDisplay value={derivedData.p2pkhAddress} title="P2PKH Address" size={40} />
                      </div>
                    </div>
                  )}

                  {derivedData.p2shAddress && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label className="text-xs text-muted-foreground">P2SH</Label>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(derivedData.p2shAddress!)}
                        >
                          <Copy size={14} />
                        </Button>
                      </div>
                      <div className="flex gap-2">
                        <Input
                          value={derivedData.p2shAddress}
                          readOnly
                          className="font-mono text-xs"
                        />
                        <QRCodeDisplay value={derivedData.p2shAddress} title="P2SH Address" size={40} />
                      </div>
                    </div>
                  )}

                  {derivedData.bech32Address && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label className="text-xs text-muted-foreground">SEGWIT (P2WPKH)</Label>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(derivedData.bech32Address!)}
                        >
                          <Copy size={14} />
                        </Button>
                      </div>
                      <div className="flex gap-2">
                        <Input
                          value={derivedData.bech32Address}
                          readOnly
                          className="font-mono text-xs"
                        />
                        <QRCodeDisplay value={derivedData.bech32Address} title="Segwit Address" size={40} />
                      </div>
                    </div>
                  )}

                  {derivedData.taprootAddress && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label className="text-xs text-muted-foreground">Taproot (P2TR)</Label>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(derivedData.taprootAddress!)}
                        >
                          <Copy size={14} />
                        </Button>
                      </div>
                      <div className="flex gap-2">
                        <Input
                          value={derivedData.taprootAddress}
                          readOnly
                          className="font-mono text-xs"
                        />
                        <QRCodeDisplay value={derivedData.taprootAddress} title="Taproot Address" size={40} />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Address Decoding */}
      <Card>
        <CardHeader>
          <CardTitle>Address Decoding</CardTitle>
          <CardDescription>
            Decode Bitcoin addresses to see their components
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="address-input">Bitcoin Address</Label>
            <Input
              id="address-input"
              value={addressInput}
              onChange={(e) => setAddressInput(e.target.value)}
              placeholder="Enter Bitcoin address to decode..."
              className="font-mono text-xs"
            />
          </div>

          {decodedAddress && (
            <>
              <Separator />
              <div className="space-y-3">
                <h4 className="text-sm font-medium">Decoded Components</h4>
                <div className="grid gap-3">
                  <div>
                    <Label className="text-xs text-muted-foreground">Address Type</Label>
                    <div className="font-mono text-sm">{decodedAddress.type}</div>
                  </div>
                  {decodedAddress.hash && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Public Key Hash</Label>
                      <div className="font-mono text-xs break-all">{decodedAddress.hash}</div>
                    </div>
                  )}
                  {decodedAddress.checksum && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Checksum</Label>
                      <div className="font-mono text-xs">{decodedAddress.checksum}</div>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Address Validation */}
      <Card>
        <CardHeader>
          <CardTitle>Address Validation</CardTitle>
          <CardDescription>
            Validate Bitcoin addresses for correctness
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="validation-input">Address to Validate</Label>
            <Input
              id="validation-input"
              value={validationInput}
              onChange={(e) => setValidationInput(e.target.value)}
              placeholder="Enter address to validate..."
              className="font-mono text-xs"
            />
          </div>

          {validationResult && (
            <>
              <Separator />
              <div className="flex items-center gap-2">
                <Badge variant={validationResult.isValid ? "default" : "destructive"}>
                  {validationResult.isValid ? "Valid" : "Invalid"}
                </Badge>
                {validationResult.error && (
                  <span className="text-sm text-muted-foreground">
                    {validationResult.error}
                  </span>
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}