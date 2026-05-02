import { useState, useEffect } from 'react'
import { Box, Stack, Typography, Alert, Paper } from '@mui/material'
import { usePersistentKV } from '@/hooks/usePersistentKV'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Copy, Shuffle, ArrowRight, Sparkle } from '@phosphor-icons/react'
import {
  generateMiniKey,
  validateMiniKey,
  miniKeyToPrivateKey,
} from '@/lib/mini-key'
import { privateKeyFromHex, encodeWif, BitcoinKeyData } from '@/lib/keys'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

export function MiniKeyPage() {
  // Persistent inputs using local storage
  const [miniKeyInput, setMiniKeyInput] = usePersistentKV('mini-key-input', '')
  const [validation, setValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })
  const [derivedData, setDerivedData] = useState<BitcoinKeyData | null>(null)
  const [compressedWif, setCompressedWif] = useState('')
  const [uncompressedWif, setUncompressedWif] = useState('')

  // Handle mini key input and validation
  useEffect(() => {
    const processInput = async () => {
      if (miniKeyInput) {
        const validationResult = await validateMiniKey(miniKeyInput)
        setValidation(validationResult)

        if (validationResult.valid) {
          const privateKeyHex = await miniKeyToPrivateKey(miniKeyInput)
          if (privateKeyHex) {
            const keyData = await privateKeyFromHex(privateKeyHex)
            setDerivedData(keyData)

            // Calculate WIF values for display
            const compWif = await encodeWif(privateKeyHex, true)
            const uncompWif = await encodeWif(privateKeyHex, false)
            setCompressedWif(compWif || '')
            setUncompressedWif(uncompWif || '')
          } else {
            setDerivedData(null)
            setCompressedWif('')
            setUncompressedWif('')
          }
        } else {
          setDerivedData(null)
          setCompressedWif('')
          setUncompressedWif('')
        }
      } else {
        setValidation({ valid: false })
        setDerivedData(null)
        setCompressedWif('')
        setUncompressedWif('')
      }
    }

    processInput()
  }, [miniKeyInput])

  const generateRandom = async () => {
    const randomMiniKey = await generateMiniKey()
    setMiniKeyInput(randomMiniKey)
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(console.error)
    }
  }

  return (
    <Stack spacing={4}>
      <Box sx={{ textAlign: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>Mini Key</Typography>
        <Typography color="text.secondary">
          Demonstrates Bitcoin mini private key generation, validation and key derivation.
        </Typography>
      </Box>

      {/* Mini Key Generation Section */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Sparkle />
            Mini Key Generation
          </CardTitle>
          <CardDescription>
            Generate a valid 30-character Bitcoin mini key that passes all validation checks
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={3}>
            <Stack spacing={2}>
              <Box sx={{ textAlign: 'center' }}>
                <Button onClick={generateRandom} size="lg" sx={{ width: '100%' }}>
                  <Sparkle size={16} style={{ marginRight: 8 }} />
                  Generate Random Mini Key
                </Button>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                  Creates a cryptographically valid mini key and populates the derivation section below
                </Typography>
              </Box>

              {miniKeyInput && (
                <Stack spacing={1}>
                  <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Generated Mini Key</Typography>
                  <Stack direction="row" spacing={2} alignItems="flex-start">
                    <Stack spacing={1} sx={{ flex: 1 }}>
                      <Stack direction="row" spacing={1}>
                        <Box component="code" sx={{ flex: 1, p: 1.5, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all', border: '1px solid', borderColor: 'primary.light' }}>
                          {miniKeyInput}
                        </Box>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(miniKeyInput)} title="Copy">
                          <Copy size={16} />
                        </Button>
                      </Stack>
                      <Typography variant="caption" color="text.secondary">
                        This mini key has been automatically populated in the derivation section below
                      </Typography>
                    </Stack>
                    <QRCodeDisplay value={miniKeyInput} title="Mini Key" size={100} />
                  </Stack>
                </Stack>
              )}
            </Stack>

            <Alert severity="info">
              <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Mini Key Format Requirements</Typography>
              <Typography variant="body2">• Exactly 30 characters long</Typography>
              <Typography variant="body2">• Must start with the character &apos;S&apos;</Typography>
              <Typography variant="body2">• All characters must be from the Base58 alphabet</Typography>
              <Typography variant="body2">• Must pass cryptographic check: SHA256(minikey + &apos;?&apos;) first byte = 0</Typography>
            </Alert>
          </Stack>
        </CardContent>
      </Card>

      {/* Mini Key Derivation Section */}
      <Card>
        <CardHeader>
          <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ArrowRight />
            Mini Key Private Key Derivation
          </CardTitle>
          <CardDescription>
            Enter or use the generated mini key above to derive the private key
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Stack spacing={3}>
            <Stack spacing={1}>
              <Label htmlFor="mini-key-input">Mini Key</Label>
              <Stack direction="row" spacing={1}>
                <Input
                  id="mini-key-input"
                  value={miniKeyInput}
                  onChange={(e) => setMiniKeyInput(e.target.value)}
                  placeholder="30-character mini key starting with 'S' (or use generator above)"
                  sx={{ '& input': { fontFamily: 'monospace', fontSize: '0.875rem' } }}
                  inputProps={{ maxLength: 30 }}
                />
                <Button variant="outline" size="icon" onClick={generateRandom} title="Generate Random">
                  <Shuffle size={16} />
                </Button>
              </Stack>
              <Typography variant="caption" color="text.secondary">
                Mini keys are exactly 30 characters long and start with &apos;S&apos;. Use the generator above or enter manually.
              </Typography>
            </Stack>

            <Stack spacing={1}>
              <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Validation Status</Typography>
              <Stack direction="row" spacing={1} alignItems="center">
                <Badge variant={validation.valid ? 'default' : miniKeyInput ? 'destructive' : 'secondary'}>
                  {!miniKeyInput ? 'No Input' : validation.valid ? 'Valid' : 'Invalid'}
                </Badge>
                {validation.error && (
                  <Typography variant="body2" color="error.main" component="span">{validation.error}</Typography>
                )}
              </Stack>
            </Stack>

            {miniKeyInput && (
              <Stack spacing={3}>
                <Separator />

                <Alert severity="info">
                  <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Mini Key Validation Rules</Typography>
                  <Typography variant="body2" color={miniKeyInput.length === 30 ? 'success.main' : 'error.main'}>
                    {miniKeyInput.length === 30 ? '✓' : '✗'} Length: {miniKeyInput.length}/30 characters
                  </Typography>
                  <Typography variant="body2" color={miniKeyInput.startsWith('S') ? 'success.main' : 'error.main'}>
                    {miniKeyInput.startsWith('S') ? '✓' : '✗'} Starts with &apos;S&apos;: {miniKeyInput.charAt(0) || 'N/A'}
                  </Typography>
                  <Typography variant="body2" color={/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$/.test(miniKeyInput) ? 'success.main' : 'error.main'}>
                    {/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$/.test(miniKeyInput) ? '✓' : '✗'} Base58 characters only
                  </Typography>
                  <Typography variant="body2" color={validation.valid ? 'success.main' : 'error.main'}>
                    {validation.valid ? '✓' : '✗'} Cryptographic check: SHA256(minikey + &apos;?&apos;) first byte = 0
                  </Typography>
                </Alert>

                {derivedData && validation.valid && (
                  <Stack spacing={3}>
                    <Separator />
                    <Typography variant="h6">Derived Private Key</Typography>

                    <Stack spacing={0.5}>
                      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Mini Key Input</Typography>
                      <Stack direction="row" spacing={1}>
                        <Box component="code" sx={{ flex: 1, p: 1.5, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all', border: '1px solid', borderColor: 'primary.light' }}>
                          {miniKeyInput}
                        </Box>
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(miniKeyInput)} title="Copy">
                          <Copy size={16} />
                        </Button>
                      </Stack>
                      <Typography variant="caption" color="text.secondary">30-character compact private key format</Typography>
                    </Stack>

                    <Paper variant="outlined" sx={{ p: 2 }}>
                      <Typography variant="subtitle2" sx={{ mb: 1.5 }}>Private Key Derivation Process</Typography>
                      <Stack spacing={1.5}>
                        <Stack direction="row" spacing={2} alignItems="center">
                          <Box component="span" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', bgcolor: 'primary.50', px: 1, py: 0.5, borderRadius: 1, border: '1px solid', borderColor: 'primary.200', whiteSpace: 'nowrap' }}>Step 1</Box>
                          <Typography variant="body2">Take the mini key: <Box component="code" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', px: 0.5, py: 0.25, borderRadius: 0.5, fontSize: '0.75rem' }}>{miniKeyInput}</Box></Typography>
                        </Stack>
                        <Stack direction="row" spacing={2} alignItems="center">
                          <Box component="span" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', bgcolor: 'primary.50', px: 1, py: 0.5, borderRadius: 1, border: '1px solid', borderColor: 'primary.200', whiteSpace: 'nowrap' }}>Step 2</Box>
                          <Typography variant="body2">Apply SHA256 hash function</Typography>
                        </Stack>
                        <Stack direction="row" spacing={2} alignItems="center">
                          <Box component="span" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', bgcolor: 'primary.50', px: 1, py: 0.5, borderRadius: 1, border: '1px solid', borderColor: 'primary.200', whiteSpace: 'nowrap' }}>Step 3</Box>
                          <Typography variant="body2">Result is the 32-byte private key in hexadecimal format</Typography>
                        </Stack>
                      </Stack>
                    </Paper>

                    <Box sx={{ textAlign: 'center' }}>
                      <ArrowRight size={20} />
                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>SHA256(mini_key)</Typography>
                    </Box>

                    <Stack spacing={0.5}>
                      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Private Key (Hex)</Typography>
                      <Stack direction="row" spacing={2} alignItems="flex-start">
                        <Stack spacing={1} sx={{ flex: 1 }}>
                          <Stack direction="row" spacing={1}>
                            <Box component="code" sx={{ flex: 1, p: 1.5, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                              {derivedData.privateKeyHex}
                            </Box>
                            <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.privateKeyHex || '')} title="Copy">
                              <Copy size={16} />
                            </Button>
                          </Stack>
                          <Typography variant="caption" color="text.secondary">32-byte private key derived from mini key</Typography>
                        </Stack>
                        <QRCodeDisplay value={derivedData.privateKeyHex || ''} title="Private Key" size={100} />
                      </Stack>
                    </Stack>

                    <Stack spacing={1}>
                      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>WIF Formats</Typography>
                      <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
                        <Stack spacing={1} sx={{ flex: 1 }}>
                          <Typography variant="caption" color="text.secondary">Compressed WIF</Typography>
                          <Stack direction="row" spacing={2} alignItems="flex-start">
                            <Stack direction="row" spacing={1} sx={{ flex: 1 }}>
                              <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all', border: '1px solid', borderColor: 'primary.light' }}>
                                {derivedData.privateKeyWif}
                              </Box>
                              <Button variant="outline" size="icon" onClick={() => copyToClipboard(derivedData.privateKeyWif || '')} title="Copy">
                                <Copy size={16} />
                              </Button>
                            </Stack>
                            <QRCodeDisplay value={derivedData.privateKeyWif || ''} title="Compressed WIF" size={80} />
                          </Stack>
                        </Stack>

                        <Stack spacing={1} sx={{ flex: 1 }}>
                          <Typography variant="caption" color="text.secondary">Uncompressed WIF</Typography>
                          <Stack direction="row" spacing={2} alignItems="flex-start">
                            <Stack direction="row" spacing={1} sx={{ flex: 1 }}>
                              <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all', border: '1px solid', borderColor: 'primary.light' }}>
                                {uncompressedWif}
                              </Box>
                              <Button variant="outline" size="icon" onClick={() => copyToClipboard(uncompressedWif)} title="Copy">
                                <Copy size={16} />
                              </Button>
                            </Stack>
                            <QRCodeDisplay value={uncompressedWif} title="Uncompressed WIF" size={80} />
                          </Stack>
                        </Stack>
                      </Stack>
                    </Stack>
                  </Stack>
                )}
              </Stack>
            )}

            <Alert severity="warning">
              <Typography variant="subtitle2" sx={{ mb: 0.5 }}>About Bitcoin Mini Keys</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                Mini keys are a compact way to represent Bitcoin private keys, historically used by some applications
                like Casascius physical bitcoins. They are 30 characters long and start with &apos;S&apos;.
              </Typography>
              <Typography variant="body2">
                The format includes a built-in check: SHA256(minikey + &apos;?&apos;) must have a first byte of 0x00.
                This provides roughly 99.6% rejection of invalid strings.
              </Typography>
            </Alert>
          </Stack>
        </CardContent>
      </Card>
    </Stack>
  )
}
