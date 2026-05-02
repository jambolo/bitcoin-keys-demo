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
  encodeWif,
  decodeWif,
  validateWif,
  generateWifSteps,
  isValidHex
} from '@/lib/keys'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

export function PrivateKeyPage() {
  // Persistent inputs using local storage
  const [privateKeyHex, setPrivateKeyHex] = usePersistentKV('private-key-hex', '')
  const [wifInput, setWifInput] = usePersistentKV('private-key-wif-input', '')
  const [validationInput, setValidationInput] = usePersistentKV('private-key-validation-input', '')

  // Shared state for compressed WIF to be used by Public Key page
  const [sharedCompressedWif, setSharedCompressedWif] = usePersistentKV('shared-compressed-wif', '')

  // Encoding section
  const [compressedWif, setCompressedWif] = useState('')
  const [uncompressedWif, setUncompressedWif] = useState('')
  const [compressedSteps, setCompressedSteps] = useState<any>(null)
  const [uncompressedSteps, setUncompressedSteps] = useState<any>(null)

  // Decoding section
  const [decodedData, setDecodedData] = useState<any>(null)

  // Validation section
  const [validation, setValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })

  // Sync with shared compressed WIF from other pages (only if it represents a different private key)
  useEffect(() => {
    const syncWithShared = async () => {
      if (sharedCompressedWif && privateKeyHex) {
        // Check if the shared WIF corresponds to the current private key
        const currentCompressed = await encodeWif(privateKeyHex, true)
        if (currentCompressed !== sharedCompressedWif) {
          // Different keys, sync from shared state
          const decoded = await decodeWif(sharedCompressedWif)
          if (decoded) {
            setPrivateKeyHex(decoded.privateKeyHex)
          }
        }
      } else if (sharedCompressedWif && !privateKeyHex) {
        // No current private key, sync from shared state
        const decoded = await decodeWif(sharedCompressedWif)
        if (decoded) {
          setPrivateKeyHex(decoded.privateKeyHex)
        }
      }
    }

    syncWithShared()
  }, [sharedCompressedWif, privateKeyHex, setPrivateKeyHex])

  // Initialize with random private key only on first ever load when no keys exist
  useEffect(() => {
    const initializeRandomKey = async () => {
      if (!privateKeyHex && !sharedCompressedWif) {
        const randomWif = await generateRandomPrivateKey()
        const decoded = await decodeWif(randomWif)
        if (decoded) {
          setPrivateKeyHex(decoded.privateKeyHex)
        }
      }
    }

    initializeRandomKey()
  }, [privateKeyHex, sharedCompressedWif, setPrivateKeyHex])

  // Handle private key hex input
  useEffect(() => {
    const updateWif = async () => {
      if (privateKeyHex && isValidHex(privateKeyHex, 64)) {
        const compressed = await encodeWif(privateKeyHex, true)
        const uncompressed = await encodeWif(privateKeyHex, false)
        const cSteps = await generateWifSteps(privateKeyHex, true)
        const uSteps = await generateWifSteps(privateKeyHex, false)

        setCompressedWif(compressed || '')
        setUncompressedWif(uncompressed || '')
        setCompressedSteps(cSteps)
        setUncompressedSteps(uSteps)

        // Update shared compressed WIF for Public Key page (only if different)
        if (compressed && compressed !== sharedCompressedWif) {
          setSharedCompressedWif(compressed)
        }
        setWifInput(compressed || '')
        setValidationInput(compressed || '')
      } else {
        setCompressedWif('')
        setUncompressedWif('')
        setCompressedSteps(null)
        setUncompressedSteps(null)
        // Clear WIF inputs when private key is invalid
        setWifInput('')
        setValidationInput('')
        // Don't clear shared state here to preserve cross-page functionality
      }
    }

    updateWif()
  }, [privateKeyHex])

  // Handle WIF input
  useEffect(() => {
    const processWif = async () => {
      if (wifInput) {
        const decoded = await decodeWif(wifInput)
        setDecodedData(decoded)
      } else {
        setDecodedData(null)
      }
    }

    processWif()
  }, [wifInput])

  // Handle validation input
  useEffect(() => {
    const validateInput = async () => {
      if (validationInput) {
        const result = await validateWif(validationInput)
        setValidation(result)
      } else {
        setValidation({ valid: false })
      }
    }

    validateInput()
  }, [validationInput])

  const generateRandom = async () => {
    const randomWif = await generateRandomPrivateKey()
    const decoded = await decodeWif(randomWif)
    if (decoded) {
      setPrivateKeyHex(decoded.privateKeyHex)
    }
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(console.error)
    }
  }

  return (
    <Stack spacing={4}>
      <Box sx={{ textAlign: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>Private Key</Typography>
        <Typography color="text.secondary">
          Demonstrates Bitcoin private key encoding, decoding, and validation using WIF format.
        </Typography>
      </Box>

      {/* WIF Encoding Section */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ArrowRight />
            WIF Encoding
          </CardTitle>
          <CardDescription>
            Convert a private key from hexadecimal format to Wallet Import Format (WIF)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={3}>
            <Box sx={{ maxWidth: { md: '50%' } }}>
              <Stack spacing={1}>
                <Label htmlFor="private-key-hex">Private Key (Hex)</Label>
                <Stack direction="row" spacing={1}>
                  <Input
                    id="private-key-hex"
                    value={privateKeyHex}
                    onChange={(e) => setPrivateKeyHex(e.target.value)}
                    placeholder="64 character hexadecimal private key"
                    sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.875rem' } }}
                  />
                  <Button variant="outline" size="icon" onClick={generateRandom} title="Generate Random">
                    <Shuffle size={16} />
                  </Button>
                </Stack>
              </Stack>
            </Box>

            {privateKeyHex && isValidHex(privateKeyHex, 64) && (
              <Stack spacing={3}>
                <Separator />
                <Stack direction={{ xs: 'column', xl: 'row' }} spacing={4}>
                  {/* Compressed WIF */}
                  <Stack spacing={2} sx={{ flex: 1 }}>
                    <Typography variant="h6">Compressed WIF Process</Typography>
                    {compressedSteps && (
                      <Stack spacing={2}>
                        <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 1: Add Prefix &amp; Compression Flag
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {compressedSteps.step1}
                            </Box>
                          </Stack>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 2: Double SHA256 Hash
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {compressedSteps.step2}
                            </Box>
                          </Stack>
                        </Stack>
                        <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 3: Checksum (First 4 bytes)
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {compressedSteps.step3}
                            </Box>
                          </Stack>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 4: Add Checksum
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {compressedSteps.step4}
                            </Box>
                          </Stack>
                        </Stack>
                        <Stack direction="row" spacing={2} alignItems="flex-start">
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Final: Base58 Encoded WIF (Compressed)
                            </Typography>
                            <Stack direction="row" spacing={1}>
                              <Box component="code" sx={{ flex: 1, p: 1.5, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all', border: '1px solid', borderColor: 'primary.light' }}>
                                {compressedWif}
                              </Box>
                              <Button variant="outline" size="icon" onClick={() => copyToClipboard(compressedWif)} title="Copy">
                                <Copy size={16} />
                              </Button>
                            </Stack>
                          </Stack>
                          <QRCodeDisplay value={compressedWif} title="Compressed WIF" size={100} />
                        </Stack>
                      </Stack>
                    )}
                  </Stack>

                  {/* Uncompressed WIF */}
                  <Stack spacing={2} sx={{ flex: 1 }}>
                    <Typography variant="h6">Uncompressed WIF Process</Typography>
                    {uncompressedSteps && (
                      <Stack spacing={2}>
                        <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 1: Add Prefix
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {uncompressedSteps.step1}
                            </Box>
                          </Stack>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 2: Double SHA256 Hash
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {uncompressedSteps.step2}
                            </Box>
                          </Stack>
                        </Stack>
                        <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 3: Checksum (First 4 bytes)
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {uncompressedSteps.step3}
                            </Box>
                          </Stack>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Step 4: Add Checksum
                            </Typography>
                            <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {uncompressedSteps.step4}
                            </Box>
                          </Stack>
                        </Stack>
                        <Stack direction="row" spacing={2} alignItems="flex-start">
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                              Final: Base58 Encoded WIF (Uncompressed)
                            </Typography>
                            <Stack direction="row" spacing={1}>
                              <Box component="code" sx={{ flex: 1, p: 1.5, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all', border: '1px solid', borderColor: 'primary.light' }}>
                                {uncompressedWif}
                              </Box>
                              <Button variant="outline" size="icon" onClick={() => copyToClipboard(uncompressedWif)} title="Copy">
                                <Copy size={16} />
                              </Button>
                            </Stack>
                          </Stack>
                          <QRCodeDisplay value={uncompressedWif} title="Uncompressed WIF" size={100} />
                        </Stack>
                      </Stack>
                    )}
                  </Stack>
                </Stack>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* WIF Decoding Section */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ArrowRight />
            WIF Decoding
          </CardTitle>
          <CardDescription>Decode a WIF private key to see its components</CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={2}>
            <Stack spacing={1}>
              <Label htmlFor="wif-input">WIF Private Key</Label>
              <Input
                id="wif-input"
                value={wifInput}
                onChange={(e) => setWifInput(e.target.value)}
                placeholder="Enter WIF format private key"
                sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.875rem' } }}
              />
            </Stack>

            {decodedData && (
              <Stack spacing={2}>
                <Separator />
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ flexWrap: 'wrap' }}>
                  <Stack spacing={0.5} sx={{ flex: '1 1 40%' }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Prefix</Typography>
                    <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace' }}>0x80</Box>
                  </Stack>
                  <Stack spacing={0.5} sx={{ flex: '1 1 40%' }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Private Key (Hex)</Typography>
                    <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {decodedData.privateKeyHex}
                    </Box>
                  </Stack>
                  <Stack spacing={0.5} sx={{ flex: '1 1 40%' }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Compression Flag</Typography>
                    <Box>
                      <Badge variant={decodedData.compressed ? 'default' : 'secondary'}>
                        {decodedData.compressed ? 'Compressed' : 'Uncompressed'}
                      </Badge>
                    </Box>
                  </Stack>
                  <Stack spacing={0.5} sx={{ flex: '1 1 40%' }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Checksum</Typography>
                    <Box component="code" sx={{ display: 'block', p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace' }}>
                      {decodedData.checksum}
                    </Box>
                  </Stack>
                </Stack>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* WIF Validation Section */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ArrowRight />
            WIF Validation
          </CardTitle>
          <CardDescription>Validate any string as a potential WIF private key</CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={2}>
            <Stack spacing={1}>
              <Label htmlFor="validation-input">String to Validate</Label>
              <Input
                id="validation-input"
                value={validationInput}
                onChange={(e) => setValidationInput(e.target.value)}
                placeholder="Enter any string to validate as WIF"
                sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.875rem' } }}
              />
            </Stack>

            {validationInput && (
              <Stack spacing={1}>
                <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                  Validation Result
                </Typography>
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
            )}
          </Stack>
        </CardContent>
      </Card>
    </Stack>
  )
}