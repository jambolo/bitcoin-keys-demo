import { useState, useEffect } from 'react'
import { Box, Stack, Typography } from '@mui/material'
import { usePersistentKV } from '@/hooks/usePersistentKV'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Copy, Shuffle, ArrowRight } from '@phosphor-icons/react'
import {   doubleSha256 } from '@/lib/crypto'
import {
  generateRandomPrivateKey,
  privateKeyFromWif,
  privateKeyFromHex,
  isValidHex,
  BitcoinKeyData,
} from '@/lib/keys'
import {
  validateBitcoinAddress,
  decodeAddress,
  generateAddresses,
} from '@/lib/address'
import { encodeBase58 } from '@/lib/base58'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

export function AddressPage() {
  // Persistent inputs using local storage
  const [wifInput, setWifInput] = usePersistentKV('address-wif-input', '')
  const [hexInput, setHexInput] = usePersistentKV('address-hex-input', '')
  const [pubkeyInput, setPubkeyInput] = usePersistentKV('address-pubkey-input', '')
  const [hashInput, setHashInput] = usePersistentKV('address-hash-input', '')
  const [addressInput, setAddressInput] = usePersistentKV('address-decode-input', '')
  const [validationInput, setValidationInput] = usePersistentKV('address-validation-input', '')

  // Derived data state
  const [derivedData, setDerivedData] = useState<BitcoinKeyData | null>(null)
  const [decodedAddress, setDecodedAddress] = useState<any>(null)
  const [validationResult, setValidationResult] = useState<{ isValid: boolean; error?: string } | null>(null)

  // Shared state - get taproot address from other pages if available
  const [sharedTaprootAddress] = usePersistentKV('shared-taproot-address', '')
  // Get shared compressed WIF from other pages
  const [sharedCompressedWif] = usePersistentKV('shared-compressed-wif', '')

  // Sync with shared compressed WIF from other pages
  useEffect(() => {
    if (sharedCompressedWif && !wifInput) {
      setWifInput(sharedCompressedWif)
    }
  }, [sharedCompressedWif, wifInput, setWifInput])

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
          const p2pkhAddress = encodeBase58(p2pkhWithChecksum)

          // Generate P2SH address
          const p2shPayload = new Uint8Array(21)
          p2shPayload[0] = 0x05
          p2shPayload.set(hash, 1)
          const p2shChecksum = await doubleSha256(p2shPayload)
          const p2shWithChecksum = new Uint8Array(25)
          p2shWithChecksum.set(p2shPayload)
          p2shWithChecksum.set(p2shChecksum.slice(0, 4), 21)
          const p2shAddress = encodeBase58(p2shWithChecksum)

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
    const validateAddress = async () => {
      if (validationInput) {
        const result = await validateBitcoinAddress(validationInput)
        setValidationResult({ isValid: result.valid, error: result.error })
      } else {
        setValidationResult(null)
      }
    }

    validateAddress()
  }, [validationInput])

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <Stack spacing={3}>
      {/* Address Derivation */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            Address Derivation
            <Button variant="outline" size="sm" onClick={handleRandomKey} sx={{ ml: 'auto' }}>
              <Shuffle size={16} style={{ marginRight: 4 }} />
              Random
            </Button>
          </CardTitle>
          <CardDescription>
            Generate Bitcoin addresses from private keys, public keys, or public key hashes
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={3}>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
              <Stack spacing={1} sx={{ flex: 1 }}>
                <Label htmlFor="wif-input">Private Key (WIF)</Label>
                <Input
                  id="wif-input"
                  value={wifInput}
                  onChange={(e) => setWifInput(e.target.value)}
                  placeholder="Enter WIF private key..."
                  sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                />
              </Stack>
              <Stack spacing={1} sx={{ flex: 1 }}>
                <Label htmlFor="hex-input">Private Key (Hex)</Label>
                <Input
                  id="hex-input"
                  value={hexInput}
                  onChange={(e) => setHexInput(e.target.value)}
                  placeholder="Enter hex private key..."
                  sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                />
              </Stack>
              <Stack spacing={1} sx={{ flex: 1 }}>
                <Label htmlFor="pubkey-input">Public Key (Hex)</Label>
                <Input
                  id="pubkey-input"
                  value={pubkeyInput}
                  onChange={(e) => setPubkeyInput(e.target.value)}
                  placeholder="Enter public key..."
                  sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                />
              </Stack>
              <Stack spacing={1} sx={{ flex: 1 }}>
                <Label htmlFor="hash-input">Derived Public Key Hash (Hex)</Label>
                <Input
                  id="hash-input"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="Enter public key hash..."
                  sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                />
              </Stack>
            </Stack>

            {derivedData && (
              <Stack spacing={2}>
                <Separator />
                <Typography variant="subtitle2">Generated Addresses</Typography>
                <Stack spacing={2}>
                  {derivedData.p2pkhAddress && (
                    <Stack spacing={0.5}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="caption" color="text.secondary">P2PKH (Legacy)</Typography>
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(derivedData.p2pkhAddress!)}>
                          <Copy size={14} />
                        </Button>
                      </Stack>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Input
                          value={derivedData.p2pkhAddress}
                          slotProps={{ input: { readOnly: true } }}
                          sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                        />
                        <QRCodeDisplay value={derivedData.p2pkhAddress} title="P2PKH Address" size={40} />
                      </Stack>
                    </Stack>
                  )}

                  {derivedData.p2shAddress && (
                    <Stack spacing={0.5}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="caption" color="text.secondary">P2SH</Typography>
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(derivedData.p2shAddress!)}>
                          <Copy size={14} />
                        </Button>
                      </Stack>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Input
                          value={derivedData.p2shAddress}
                          slotProps={{ input: { readOnly: true } }}
                          sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                        />
                        <QRCodeDisplay value={derivedData.p2shAddress} title="P2SH Address" size={40} />
                      </Stack>
                    </Stack>
                  )}

                  {derivedData.bech32Address && (
                    <Stack spacing={0.5}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="caption" color="text.secondary">SEGWIT (P2WPKH)</Typography>
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(derivedData.bech32Address!)}>
                          <Copy size={14} />
                        </Button>
                      </Stack>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Input
                          value={derivedData.bech32Address}
                          slotProps={{ input: { readOnly: true } }}
                          sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                        />
                        <QRCodeDisplay value={derivedData.bech32Address} title="Segwit Address" size={40} />
                      </Stack>
                    </Stack>
                  )}

                  {derivedData.taprootAddress && (
                    <Stack spacing={0.5}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="caption" color="text.secondary">Taproot (P2TR)</Typography>
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(derivedData.taprootAddress!)}>
                          <Copy size={14} />
                        </Button>
                      </Stack>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Input
                          value={derivedData.taprootAddress}
                          slotProps={{ input: { readOnly: true } }}
                          sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
                        />
                        <QRCodeDisplay value={derivedData.taprootAddress} title="Taproot Address" size={40} />
                      </Stack>
                    </Stack>
                  )}
                </Stack>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* Address Decoding */}
      <Card>
        <CardHeader>
          <CardTitle>Address Decoding</CardTitle>
          <CardDescription>Decode Bitcoin addresses to see their components</CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={2}>
            <Stack spacing={1}>
              <Label htmlFor="address-input">Bitcoin Address</Label>
              <Input
                id="address-input"
                value={addressInput}
                onChange={(e) => setAddressInput(e.target.value)}
                placeholder="Enter Bitcoin address to decode..."
                sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
              />
            </Stack>

            {decodedAddress && (
              <Stack spacing={2}>
                <Separator />
                <Typography variant="subtitle2">Decoded Components</Typography>
                <Stack spacing={1.5}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Address Type</Typography>
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{decodedAddress.type}</Typography>
                  </Box>
                  {decodedAddress.hash && (
                    <Box>
                      <Typography variant="caption" color="text.secondary">Public Key Hash</Typography>
                      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{decodedAddress.hash}</Typography>
                    </Box>
                  )}
                  {decodedAddress.checksum && (
                    <Box>
                      <Typography variant="caption" color="text.secondary">Checksum</Typography>
                      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{decodedAddress.checksum}</Typography>
                    </Box>
                  )}
                </Stack>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* Address Validation */}
      <Card>
        <CardHeader>
          <CardTitle>Address Validation</CardTitle>
          <CardDescription>Validate Bitcoin addresses for correctness</CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={2}>
            <Stack spacing={1}>
              <Label htmlFor="validation-input">Address to Validate</Label>
              <Input
                id="validation-input"
                value={validationInput}
                onChange={(e) => setValidationInput(e.target.value)}
                placeholder="Enter address to validate..."
                sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.75rem' } }}
              />
            </Stack>

            {validationResult && (
              <Stack spacing={1}>
                <Separator />
                <Stack direction="row" spacing={1} alignItems="center">
                  <Badge variant={validationResult.isValid ? 'default' : 'destructive'}>
                    {validationResult.isValid ? 'Valid' : 'Invalid'}
                  </Badge>
                  {validationResult.error && (
                    <Typography variant="body2" color="text.secondary">
                      {validationResult.error}
                    </Typography>
                  )}
                </Stack>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>
    </Stack>
  )
}