import { useState, useEffect } from 'react'
import { Box, Stack, Typography, Alert } from '@mui/material'
import { usePersistentKV } from '@/hooks/usePersistentKV'
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
  validatePublicKey,
  BitcoinKeyData
} from '@/lib/keys'

export function PublicKeyPage() {
  // Persistent inputs using local storage
  const [wifInput, setWifInput] = usePersistentKV('public-key-wif-input', '')
  const [publicKeyInput, setPublicKeyInput] = usePersistentKV('public-key-validation-input', '')

  const [derivedData, setDerivedData] = useState<BitcoinKeyData | null>(null)
  const [validation, setValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })

  // Get shared compressed WIF from Private Key page
  const [sharedCompressedWif, setSharedCompressedWif] = usePersistentKV('shared-compressed-wif', '')

  // Always sync with shared compressed WIF from Private Key page when it changes
  useEffect(() => {
    if (sharedCompressedWif && sharedCompressedWif !== wifInput) {
      setWifInput(sharedCompressedWif)
    }
  }, [sharedCompressedWif, wifInput, setWifInput])

  // Update shared state when local wifInput changes (unless it came from shared state)
  useEffect(() => {
    if (wifInput && wifInput !== sharedCompressedWif) {
      setSharedCompressedWif(wifInput)
    }
  }, [wifInput, sharedCompressedWif, setSharedCompressedWif])

  // Initialize with random key only on first load if no shared WIF exists
  useEffect(() => {
    const initializeWithRandom = async () => {
      if (!wifInput && !sharedCompressedWif) {
        const randomWif = await generateRandomPrivateKey()
        setWifInput(randomWif)
      }
    }

    initializeWithRandom()
  }, []) // Remove dependencies to only run once on mount

  // Handle WIF input for derivation
  useEffect(() => {
    const processWif = async () => {
      if (wifInput) {
        const data = await privateKeyFromWif(wifInput)
        setDerivedData(data)

        // Always update validation input with newly derived public key
        if (data?.publicKeyHex) {
          setPublicKeyInput(data.publicKeyHex)
        }
      } else {
        setDerivedData(null)
        setPublicKeyInput('')
      }
    }

    processWif()
  }, [wifInput, setPublicKeyInput])

  // Handle public key validation
  useEffect(() => {
    if (publicKeyInput) {
      const result = validatePublicKey(publicKeyInput)
      setValidation(result)
    } else {
      setValidation({ valid: false })
    }
  }, [publicKeyInput])

  const generateRandom = async () => {
    const randomWif = await generateRandomPrivateKey()
    setWifInput(randomWif)
    // Update shared state so Private Key page stays in sync
    setSharedCompressedWif(randomWif)
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(console.error)
    }
  }

  return (
    <Stack spacing={4}>
      <Box sx={{ textAlign: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>Public Key</Typography>
        <Typography color="text.secondary">
          Derive public keys from private keys and validate public key formats.
        </Typography>
      </Box>

      {/* Derivation Section */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ArrowRight />
            Public Key Derivation
          </CardTitle>
          <CardDescription>Derive a public key from a private key in WIF format</CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={3}>
            <Stack spacing={1}>
              <Label htmlFor="wif-derivation">Private Key (WIF)</Label>
              <Stack direction="row" spacing={1}>
                <Input
                  id="wif-derivation"
                  value={wifInput}
                  onChange={(e) => setWifInput(e.target.value)}
                  placeholder="Enter WIF format private key"
                  sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.875rem' } }}
                />
                <Button variant="outline" size="icon" onClick={generateRandom} title="Generate Random">
                  <Shuffle size={16} />
                </Button>
              </Stack>
              {sharedCompressedWif && wifInput === sharedCompressedWif && (
                <Typography variant="caption" color="primary.main">
                  Using compressed WIF from Private Key page
                </Typography>
              )}
            </Stack>

            {derivedData && (
              <Stack spacing={2}>
                <Separator />
                <Stack direction={{ xs: 'column', lg: 'row' }} spacing={3}>
                  <Stack spacing={2} sx={{ flex: 1 }}>
                    <Stack spacing={0.5}>
                      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Private Key (Hex)</Typography>
                      <Stack direction="row" spacing={1}>
                        <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                          {derivedData.privateKeyHex}
                        </Box>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.privateKeyHex || '')} title="Copy">
                          <Copy size={16} />
                        </Button>
                      </Stack>
                    </Stack>

                    <Stack spacing={0.5}>
                      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Compression Flag</Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Badge variant={derivedData.compressed ? 'default' : 'secondary'}>
                          {derivedData.compressed ? 'Compressed' : 'Uncompressed'}
                        </Badge>
                        <Typography variant="body2" color="text.secondary">
                          {derivedData.compressed ? 'Public key is 33 bytes (66 hex chars)' : 'Public key is 65 bytes (130 hex chars)'}
                        </Typography>
                      </Stack>
                    </Stack>
                  </Stack>

                  <Stack spacing={0.5} sx={{ flex: 1 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Derived Public Key</Typography>
                    <Stack direction="row" spacing={1}>
                      <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all', border: '1px solid', borderColor: 'primary.light' }}>
                        {derivedData.publicKeyHex}
                      </Box>
                      <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.publicKeyHex || '')} title="Copy">
                        <Copy size={16} />
                      </Button>
                    </Stack>
                    <Typography variant="caption" color="text.secondary">
                      {derivedData.compressed
                        ? `Starts with ${derivedData.publicKeyHex?.slice(0, 2)} (compressed prefix)`
                        : 'Starts with 04 (uncompressed prefix)'}
                    </Typography>
                    <Typography variant="caption" color="primary.main">
                      Auto-populated in validation section below
                    </Typography>
                  </Stack>
                </Stack>

                <Alert severity="info">
                  <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Derivation Process</Typography>
                  <Typography variant="body2">1. Private key → ECDSA point multiplication with generator point G</Typography>
                  <Typography variant="body2">
                    2. {derivedData.compressed ? 'Compressed format: Include only x-coordinate + prefix (02/03)' : 'Uncompressed format: Include both x and y coordinates + prefix (04)'}
                  </Typography>
                  <Typography variant="body2">3. Result: {derivedData.compressed ? '33-byte' : '65-byte'} public key</Typography>
                </Alert>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* Validation Section */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ArrowRight />
            Public Key Validation
          </CardTitle>
          <CardDescription>Validate a public key in hexadecimal format</CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={2}>
            <Stack spacing={1}>
              <Label htmlFor="pubkey-validation">Public Key (Hex)</Label>
              <Input
                id="pubkey-validation"
                value={publicKeyInput}
                onChange={(e) => setPublicKeyInput(e.target.value)}
                placeholder="Enter public key in hexadecimal format"
                sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.875rem' } }}
              />
              {derivedData?.publicKeyHex && publicKeyInput === derivedData.publicKeyHex && (
                <Typography variant="caption" color="primary.main">
                  Auto-populated from derivation section above
                </Typography>
              )}
            </Stack>

            {publicKeyInput && (
              <Stack spacing={2}>
                <Separator />
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <Stack spacing={0.5} sx={{ flex: 1 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Validation Result</Typography>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Badge variant={validation.valid ? 'default' : 'destructive'}>
                        {validation.valid ? 'Valid' : 'Invalid'}
                      </Badge>
                      {validation.error && (
                        <Typography variant="body2" color="error.main" component="span">
                          {validation.error}
                        </Typography>
                      )}
                    </Stack>
                  </Stack>

                  {validation.valid && (
                    <Stack spacing={0.5} sx={{ flex: 1 }}>
                      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Format Details</Typography>
                      <Typography variant="body2">
                        <strong>Length:</strong> {publicKeyInput.length} characters ({publicKeyInput.length / 2} bytes)
                      </Typography>
                      <Typography variant="body2">
                        <strong>Type:</strong> {
                          publicKeyInput.length === 66 ? 'Compressed' :
                          publicKeyInput.length === 130 ? 'Uncompressed' : 'Unknown'
                        }
                      </Typography>
                      <Typography variant="body2">
                        <strong>Prefix:</strong> {publicKeyInput.slice(0, 2)}
                      </Typography>
                    </Stack>
                  )}
                </Stack>

                <Alert severity="warning">
                  <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Validation Checks</Typography>
                  <Typography variant="body2">• Hexadecimal characters only (0-9, A-F)</Typography>
                  <Typography variant="body2">• Valid prefix: 02/03 (compressed) or 04 (uncompressed)</Typography>
                  <Typography variant="body2">• Correct length: 66 chars (compressed) or 130 chars (uncompressed)</Typography>
                  <Typography variant="body2">• Point lies on the secp256k1 elliptic curve</Typography>
                </Alert>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>
    </Stack>
  )
}