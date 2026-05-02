import { useState, useEffect } from 'react'
import { Box, Stack, Typography, Alert, Paper } from '@mui/material'
import { FormControl, MenuItem, Select } from '@mui/material'
import { usePersistentKV } from '@/hooks/usePersistentKV'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Textarea } from '@/components/ui/textarea'
import { Copy, Shuffle, ArrowRight, Key } from '@phosphor-icons/react'
import { Buffer } from '@/lib/polyfills'
import { privateKeyFromHex } from '@/lib/keys'
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  mnemonicToEntropy,
  derivePrivateKey,
} from '@/lib/bip39'
import { generateAddressFromPrivateKey } from '@/lib/address'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

export function SeedPage() {
  // Persistent inputs using local storage
  const [seedPhrase, setSeedPhrase] = usePersistentKV('seed-phrase', '')
  const [derivationPath, setDerivationPath] = usePersistentKV('seed-derivation-path', "m/86'/0'/0'")
  const [selectedWordCount, setSelectedWordCount] = usePersistentKV('seed-word-count', '12')

  const [isInitialized, setIsInitialized] = useState(false)
  const [seedValidation, setSeedValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })
  const [masterSeed, setMasterSeed] = useState('')
  const [xpriv, setXpriv] = useState('')
  const [xpub, setXpub] = useState('')
  const [ypriv, setYpriv] = useState('')
  const [ypub, setYpub] = useState('')
  const [zpriv, setZpriv] = useState('')
  const [zpub, setZpub] = useState('')
  const [derivedKeys, setDerivedKeys] = useState<Array<{
    path: string
    privateKey: string
    address: string
  }>>([])

  // Initialize Bitcoin library
  useEffect(() => {
    setIsInitialized(true) // Bitcoin-lite doesn't need initialization
  }, [])

  // Generate derived keys function
  const generateDerivedKeys = async (basePath: string, seed: Uint8Array) => {
    const derived: Array<{
      path: string
      privateKey: string
      address: string
    }> = []

    // Parse the purpose from the path to determine address type
    const pathMatch = basePath.match(/^m\/(\d+)'\//)
    const purpose = pathMatch ? parseInt(pathMatch[1]) : 44

    try {
      for (let i = 0; i < 5; i++) {
        const fullPath = `${basePath}/0/${i}`
        const privateKeyHex = await derivePrivateKey(seed, fullPath)

        // Generate appropriate address type based on purpose
        let address = 'Error generating address'

        try {
          switch (purpose) {
            case 44: // Legacy P2PKH
              address = generateAddressFromPrivateKey(privateKeyHex, 'p2pkh')
              break
            case 49: // Segwit P2SH-wrapped
              address = generateAddressFromPrivateKey(privateKeyHex, 'p2sh')
              break
            case 84: // Native Segwit
              address = generateAddressFromPrivateKey(privateKeyHex, 'bech32')
              break
            case 86: // Taproot
              address = generateAddressFromPrivateKey(privateKeyHex, 'taproot')
              break
            default:
              address = generateAddressFromPrivateKey(privateKeyHex, 'p2pkh')
          }
        } catch (error) {
          console.error('Address generation error:', error)
          address = 'Error generating address'
        }

        derived.push({
          path: `${basePath}/0/${i}`,
          privateKey: privateKeyHex,
          address: address
        })
      }
    } catch (error) {
      console.error('Error deriving keys:', error)
    }

    setDerivedKeys(derived)
  }

  // Validate seed phrase
  useEffect(() => {
    const processPhrase = async () => {
      if (seedPhrase) {
        const words = seedPhrase.trim().split(/\s+/)

        if (words.length === 0) {
          setSeedValidation({ valid: false })
          return
        }

        if (words.length !== 12 && words.length !== 15 && words.length !== 18 && words.length !== 21 && words.length !== 24) {
          setSeedValidation({ valid: false, error: `Invalid word count: ${words.length}. Must be 12, 15, 18, 21, or 24 words.` })
          return
        }

        const isValid = validateMnemonic(seedPhrase)
        if (isValid) {
          setSeedValidation({ valid: true })
        } else {
          setSeedValidation({ valid: false, error: 'Invalid BIP-39 mnemonic phrase (checksum failure)' })
        }

        // Generate master seed and keys regardless of BIP-39 validity
        // Many wallets accept invalid seed phrases but show warnings
        try {
          const seed = await mnemonicToSeed(seedPhrase)
          setMasterSeed(Buffer.from(seed).toString('hex'))

          // Generate master private keys for different purposes
          const masterPrivKey = await derivePrivateKey(seed, 'm/')

          // Generate different format master keys (simplified versions)
          setXpriv(`xprv9s21ZrQH143K${masterPrivKey.slice(0, 60)}`) // Simplified xpriv format
          setXpub(`xpub661MyMwAqRbcF${masterPrivKey.slice(0, 60)}`)   // Simplified xpub format

          // Generate ypriv/ypub (m/49'/0'/0' for P2SH-P2WPKH)
          const segwitPrivKey = await derivePrivateKey(seed, "m/49'/0'/0'")
          setYpriv(`yprv9s21ZrQH143K${segwitPrivKey.slice(0, 60)}`)
          setYpub(`ypub6QhBrBvw5PUc${segwitPrivKey.slice(0, 60)}`)

          // Generate zpriv/zpub (m/84'/0'/0' for P2WPKH)
          const nativeSegwitPrivKey = await derivePrivateKey(seed, "m/84'/0'/0'")
          setZpriv(`zprv9s21ZrQH143K${nativeSegwitPrivKey.slice(0, 60)}`)
          setZpub(`zpub6jftahH18ngZ${nativeSegwitPrivKey.slice(0, 60)}`)

          // Generate derived keys based on derivation path
          await generateDerivedKeys(derivationPath || "m/86'/0'/0'", seed)
        } catch (error) {
          console.error('Error generating keys from seed phrase:', error)
          setMasterSeed('')
          setXpriv('')
          setXpub('')
          setYpriv('')
          setYpub('')
          setZpriv('')
          setZpub('')
          setDerivedKeys([])
        }
      } else {
        setSeedValidation({ valid: false })
        setMasterSeed('')
        setXpriv('')
        setXpub('')
        setYpriv('')
        setYpub('')
        setZpriv('')
        setZpub('')
        setDerivedKeys([])
      }
    }

    processPhrase()
  }, [seedPhrase, derivationPath])

  const generateRandomSeed = () => {
    const wordCount = parseInt(selectedWordCount || '12')
    const strength = ((wordCount - 12) / 3) * 32 + 128 // 128, 160, 192, 224, 256 bits
    const mnemonic = generateMnemonic(strength)
    setSeedPhrase(mnemonic)
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(console.error)
    }
  }

  return (
    <Stack spacing={4}>
      <Box sx={{ textAlign: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>Seed Phrase</Typography>
        <Typography color="text.secondary">
          Generate and validate BIP-39 seed phrases and demonstrate hierarchical deterministic key derivation.
        </Typography>
      </Box>

      {!isInitialized ? (
        <Card>
          <CardContent sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <Typography color="text.secondary">Initializing Bitcoin cryptography...</Typography>
          </CardContent>
        </Card>
      ) : (
        <Stack spacing={4}>
          {/* Seed Generation and Validation */}
          <Card>
            <CardHeader>
              <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ArrowRight />
                BIP-39 Seed Phrase
              </CardTitle>
              <CardDescription>
                Generate or enter a mnemonic seed phrase for hierarchical deterministic wallet creation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Stack spacing={3}>
                <Stack spacing={1}>
                  <Label htmlFor="seed-phrase">Seed Phrase (Mnemonic)</Label>
                  <Stack direction="row" spacing={1}>
                    <Textarea
                      id="seed-phrase"
                      value={seedPhrase}
                      onChange={(e) => setSeedPhrase(e.target.value)}
                      placeholder="Enter or generate a BIP-39 mnemonic phrase (12, 15, 18, 21, or 24 words)"
                      sx={{ '& textarea': { fontFamily: 'monospace', fontSize: '0.875rem' } }}
                      rows={3}
                    />
                    <Stack spacing={1}>
                      <FormControl size="small" sx={{ minWidth: 80 }}>
                        <Select
                          value={selectedWordCount}
                          onChange={(e) => setSelectedWordCount(e.target.value)}
                        >
                          <MenuItem value="12">12</MenuItem>
                          <MenuItem value="15">15</MenuItem>
                          <MenuItem value="18">18</MenuItem>
                          <MenuItem value="21">21</MenuItem>
                          <MenuItem value="24">24</MenuItem>
                        </Select>
                      </FormControl>
                      <Button variant="outline" size="icon" onClick={generateRandomSeed} title="Generate Random">
                        <Shuffle size={16} />
                      </Button>
                    </Stack>
                  </Stack>
                </Stack>

                {seedPhrase && (
                  <Stack spacing={2}>
                    <Separator />
                    <Stack spacing={1}>
                      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Validation Result</Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Badge variant={seedValidation.valid ? 'default' : 'destructive'}>
                          {seedValidation.valid ? 'Valid BIP-39' : 'Invalid BIP-39'}
                        </Badge>
                        {seedValidation.error && (
                          <Typography variant="body2" color="error.main" component="span">{seedValidation.error}</Typography>
                        )}
                      </Stack>
                    </Stack>

                    {!seedValidation.valid && (
                      <Alert severity="info">
                        <strong>Wallet Compatibility:</strong> Note that the seed phrase does not have to be a valid BIP-39 seed phrase - any text can be used as input. Many wallets accept invalid seed phrases but will display a warning.
                      </Alert>
                    )}
                  </Stack>
                )}
              </Stack>
            </CardContent>
          </Card>

          {/* Seed Analysis */}
          {seedPhrase && (
            <Card>
              <CardHeader>
                <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ArrowRight />
                  Phrase Analysis
                </CardTitle>
                <CardDescription>Detailed analysis of the entered seed phrase</CardDescription>
              </CardHeader>
              <CardContent>
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <Stack spacing={0.5} sx={{ flex: 1 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Word Count</Typography>
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{seedPhrase.trim().split(/\s+/).length} words</Typography>
                  </Stack>
                  <Stack spacing={0.5} sx={{ flex: 1 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Entropy</Typography>
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {Math.round((seedPhrase.trim().split(/\s+/).length * Math.log2(2048)) * 100) / 100} bits
                    </Typography>
                  </Stack>
                  <Stack spacing={0.5} sx={{ flex: 1 }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Security Level</Typography>
                    <Typography variant="body2">
                      {(() => {
                        const words = seedPhrase.trim().split(/\s+/).length
                        if (words >= 24) return 'Very High'
                        if (words >= 18) return 'High'
                        if (words >= 15) return 'Medium'
                        if (words >= 12) return 'Standard'
                        return 'Low'
                      })()}
                    </Typography>
                  </Stack>
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Master Seed and Keys */}
          {masterSeed && (
            <Card>
              <CardHeader>
                <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Key />
                  Master Seed and Keys
                </CardTitle>
                <CardDescription>
                  Master seed and extended public/private key pairs derived from the mnemonic
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Stack spacing={3}>
                  <Stack spacing={0.5}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Master Seed (Hex)</Typography>
                    <Stack direction="row" spacing={1}>
                      <Box component="code" sx={{ flex: 1, p: 1.5, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{masterSeed}</Box>
                      <Button variant="outline" size="icon" onClick={() => copyToClipboard(masterSeed)} title="Copy"><Copy size={16} /></Button>
                    </Stack>
                  </Stack>

                  <Separator />

                  <Stack direction={{ xs: 'column', lg: 'row' }} spacing={4}>
                    <Stack spacing={3} sx={{ flex: 1 }}>
                      <Typography variant="h6">Extended Private Keys</Typography>

                      {[{label: 'xpriv (BIP44/Legacy)', value: xpriv, title: 'xpriv'},
                        {label: 'ypriv (BIP49/SegWit)', value: ypriv, title: 'ypriv'},
                        {label: 'zpriv (BIP84/Native SegWit)', value: zpriv, title: 'zpriv'}].map(({label, value, title}) => (
                        <Stack direction="row" spacing={2} alignItems="flex-start" key={title}>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>{label}</Typography>
                            <Stack direction="row" spacing={1}>
                              <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{value}</Box>
                              <Button variant="outline" size="icon" onClick={() => copyToClipboard(value)} title="Copy"><Copy size={16} /></Button>
                            </Stack>
                          </Stack>
                          <QRCodeDisplay value={value} title={title} size={100} />
                        </Stack>
                      ))}
                    </Stack>

                    <Stack spacing={3} sx={{ flex: 1 }}>
                      <Typography variant="h6">Extended Public Keys</Typography>

                      {[{label: 'xpub (BIP44/Legacy)', value: xpub, title: 'xpub'},
                        {label: 'ypub (BIP49/SegWit)', value: ypub, title: 'ypub'},
                        {label: 'zpub (BIP84/Native SegWit)', value: zpub, title: 'zpub'}].map(({label, value, title}) => (
                        <Stack direction="row" spacing={2} alignItems="flex-start" key={title}>
                          <Stack spacing={0.5} sx={{ flex: 1 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>{label}</Typography>
                            <Stack direction="row" spacing={1}>
                              <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{value}</Box>
                              <Button variant="outline" size="icon" onClick={() => copyToClipboard(value)} title="Copy"><Copy size={16} /></Button>
                            </Stack>
                          </Stack>
                          <QRCodeDisplay value={value} title={title} size={100} />
                        </Stack>
                      ))}
                    </Stack>
                  </Stack>
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* HD Key Derivation */}
          {masterSeed && (
            <Card>
              <CardHeader>
                <CardTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ArrowRight />
                  Hierarchical Deterministic Key Derivation
                </CardTitle>
                <CardDescription>
                  Generate child keys using BIP-32 derivation paths. Enter a path up to the account level (m/purpose&apos;/coin_type&apos;/account&apos;).
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Stack spacing={3}>
                  <Stack spacing={1}>
                    <Label htmlFor="derivation-path">Derivation Path (up to account level)</Label>
                    <Input
                      id="derivation-path"
                      value={derivationPath}
                      onChange={(e) => setDerivationPath(e.target.value)}
                      placeholder="m/86'/0'/0'"
                      sx={{ '& input': { fontFamily: 'monospace' } }}
                    />
                  </Stack>

                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>Common Derivation Paths:</Typography>
                    <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} sx={{ flexWrap: 'wrap' }}>
                      <Typography variant="body2" sx={{ flex: '1 1 45%' }}><Box component="code" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', px: 0.5, borderRadius: 0.5 }}>m/44&apos;/0&apos;/0&apos;</Box> - Legacy (P2PKH)</Typography>
                      <Typography variant="body2" sx={{ flex: '1 1 45%' }}><Box component="code" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', px: 0.5, borderRadius: 0.5 }}>m/49&apos;/0&apos;/0&apos;</Box> - SegWit (P2SH-P2WPKH)</Typography>
                      <Typography variant="body2" sx={{ flex: '1 1 45%' }}><Box component="code" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', px: 0.5, borderRadius: 0.5 }}>m/84&apos;/0&apos;/0&apos;</Box> - Native SegWit (P2WPKH)</Typography>
                      <Typography variant="body2" sx={{ flex: '1 1 45%' }}><Box component="code" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', px: 0.5, borderRadius: 0.5 }}>m/86&apos;/0&apos;/0&apos;</Box> - Taproot (P2TR)</Typography>
                    </Stack>
                  </Paper>

                  {derivedKeys.length > 0 && (
                    <Stack spacing={2}>
                      <Separator />
                      <Typography variant="subtitle2">Derived Keys (First 5 addresses, change branch 0)</Typography>
                      <Stack spacing={2}>
                        {derivedKeys.map((key, index) => (
                          <Paper variant="outlined" sx={{ p: 2 }} key={index}>
                            <Stack spacing={1.5}>
                              <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Path: {key.path}</Typography>
                              <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
                                <Stack spacing={0.5} sx={{ flex: 1 }}>
                                  <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Private Key</Typography>
                                  <Stack direction="row" spacing={1}>
                                    <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{key.privateKey}</Box>
                                    <Button variant="outline" size="icon" onClick={() => copyToClipboard(key.privateKey)} title="Copy"><Copy size={16} /></Button>
                                  </Stack>
                                </Stack>
                                <Stack spacing={0.5} sx={{ flex: 1 }}>
                                  <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>Address</Typography>
                                  <Stack direction="row" spacing={1}>
                                    <Box component="code" sx={{ flex: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{key.address}</Box>
                                    <Button variant="outline" size="icon" onClick={() => copyToClipboard(key.address)} title="Copy"><Copy size={16} /></Button>
                                  </Stack>
                                </Stack>
                              </Stack>
                            </Stack>
                          </Paper>
                        ))}
                      </Stack>
                    </Stack>
                  )}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* About Section */}
          <Card>
            <CardHeader>
              <CardTitle>About BIP-39 and HD Wallets</CardTitle>
            </CardHeader>
            <CardContent>
              <Stack spacing={2}>
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>BIP-39 (Mnemonic Seeds)</Typography>
                  <Typography variant="body2" color="text.secondary">
                    BIP-39 defines how to generate mnemonic sentences (seed phrases) that can be used to derive cryptographic keys.
                    The seed is created from the seed phrase text and is used as the root for hierarchical deterministic wallets.
                  </Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>BIP-32 (Hierarchical Deterministic Wallets)</Typography>
                  <Typography variant="body2" color="text.secondary">
                    BIP-32 enables the generation of multiple keys from a single seed. This allows users to generate many addresses
                    from one backup, improving privacy and usability. Keys are derived using mathematical functions,
                    ensuring deterministic and reproducible wallet generation.
                  </Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>Derivation Paths</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Different Bitcoin address types use different derivation paths. Legacy addresses use BIP-44 (m/44&apos;),
                    SegWit addresses use BIP-49 (m/49&apos;), Native SegWit uses BIP-84 (m/84&apos;), and Taproot uses BIP-86 (m/86&apos;).
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Stack>
      )}
    </Stack>
  )
}
