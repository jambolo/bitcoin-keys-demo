import { useState, useEffect } from 'react'
import { useKV } from '@github/spark/hooks'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Copy, Shuffle, ArrowRight, Key } from '@phosphor-icons/react'
import * as bip39 from 'bip39'
import { BIP32Factory } from 'bip32'
import * as ecc from 'tiny-secp256k1'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

const bip32 = BIP32Factory(ecc)

export function SeedPage() {
  // Persistent inputs using useKV
  const [seedPhrase, setSeedPhrase] = useKV('seed-phrase', '')
  const [derivationPath, setDerivationPath] = useKV('seed-derivation-path', "m/86'/0'/0'")
  const [selectedWordCount, setSelectedWordCount] = useKV('seed-word-count', '12')
  
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

  // Validate seed phrase
  useEffect(() => {
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

      const isValid = bip39.validateMnemonic(seedPhrase)
      if (isValid) {
        setSeedValidation({ valid: true })
      } else {
        setSeedValidation({ valid: false, error: 'Invalid BIP-39 mnemonic phrase (checksum failure)' })
      }
      
      // Generate master seed and keys regardless of BIP-39 validity
      // Many wallets accept invalid seed phrases but show warnings
      const seed = bip39.mnemonicToSeedSync(seedPhrase)
      setMasterSeed(seed.toString('hex'))
      
      // Generate proper BIP-32 master keys
      const masterNode = bip32.fromSeed(seed)
      
      // Generate master xpriv/xpub (at root level m/)
      setXpriv(masterNode.toBase58())
      setXpub(masterNode.neutered().toBase58())
      
      // Generate ypriv/ypub (m/49'/0'/0' for P2SH-P2WPKH)
      const segwitNode = masterNode.derivePath("m/49'/0'/0'")
      setYpriv(segwitNode.toBase58())
      setYpub(segwitNode.neutered().toBase58())
      
      // Generate zpriv/zpub (m/84'/0'/0' for P2WPKH)
      const nativeSegwitNode = masterNode.derivePath("m/84'/0'/0'")
      setZpriv(nativeSegwitNode.toBase58())
      setZpub(nativeSegwitNode.neutered().toBase58())
      
      // Generate derived keys based on derivation path
      const generateDerivedKeys = async (basePath: string) => {
        const { privateKeyFromHex } = await import('@/lib/bitcoin')
        
        const derived: Array<{
          path: string
          privateKey: string
          address: string
        }> = []
        
        // Parse the purpose from the path to determine address type
        const pathMatch = basePath.match(/^m\/(\d+)'\//)
        const purpose = pathMatch ? parseInt(pathMatch[1]) : 44
        
        try {
          const accountNode = masterNode.derivePath(basePath)
          const changeNode = accountNode.derivePath('0') // External chain (0)
          
          for (let i = 0; i < 5; i++) {
            const addressNode = changeNode.derivePath(i.toString())
            const privateKeyHex = addressNode.privateKey ? Buffer.from(addressNode.privateKey).toString('hex') : ''
            
            // Generate appropriate address type based on purpose
            const keyData = privateKeyFromHex(privateKeyHex)
            let address = 'Error generating address'
            
            if (keyData) {
              switch (purpose) {
                case 44: // Legacy P2PKH
                  address = keyData.p2pkhAddress || 'Error generating address'
                  break
                case 49: // Segwit P2SH-wrapped
                  address = keyData.p2shAddress || 'Error generating address'
                  break
                case 84: // Native Segwit P2WPKH
                  address = keyData.bech32Address || 'Error generating address'
                  break
                case 86: // Taproot P2TR
                  address = keyData.taprootAddress || 'Error generating address'
                  break
                default:
                  address = keyData.p2pkhAddress || 'Error generating address'
              }
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
      
      generateDerivedKeys(derivationPath || "m/86'/0'/0'")
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
  }, [seedPhrase, derivationPath])

  const generateRandomSeed = () => {
    const wordCount = parseInt(selectedWordCount || '12')
    const strength = ((wordCount - 12) / 3) * 32 + 128 // 128, 160, 192, 224, 256 bits
    const mnemonic = bip39.generateMnemonic(strength)
    setSeedPhrase(mnemonic)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold mb-2">Seed Phrase</h2>
        <p className="text-muted-foreground">
          Generate and validate BIP-39 seed phrases and demonstrate hierarchical deterministic key derivation.
        </p>
      </div>

      {/* Seed Generation and Validation */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            BIP-39 Seed Phrase
          </CardTitle>
          <CardDescription>
            Generate or enter a mnemonic seed phrase for hierarchical deterministic wallet creation
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="seed-phrase">Seed Phrase (Mnemonic)</Label>
            <div className="flex gap-2">
              <Textarea
                id="seed-phrase"
                value={seedPhrase}
                onChange={(e) => setSeedPhrase(e.target.value)}
                placeholder="Enter or generate a BIP-39 mnemonic phrase (12, 15, 18, 21, or 24 words)"
                className="font-mono text-sm min-h-[80px]"
                rows={3}
              />
              <div className="flex flex-col gap-2">
                <Select value={selectedWordCount} onValueChange={setSelectedWordCount}>
                  <SelectTrigger className="w-20">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="12">12</SelectItem>
                    <SelectItem value="15">15</SelectItem>
                    <SelectItem value="18">18</SelectItem>
                    <SelectItem value="21">21</SelectItem>
                    <SelectItem value="24">24</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={generateRandomSeed}
                  title="Generate Random"
                >
                  <Shuffle size={16} />
                </Button>
              </div>
            </div>
            <div className="text-xs text-muted-foreground">
              BIP-39 mnemonic phrases use a standardized word list for generating seeds. Select word count and click shuffle to generate.
            </div>
          </div>

          {/* Validation Status */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wide text-muted-foreground">Validation Status</Label>
            <div className="flex items-center gap-2">
              <Badge variant={seedValidation.valid ? "default" : seedPhrase ? "destructive" : "secondary"}>
                {!seedPhrase ? 'No Input' : seedValidation.valid ? 'Valid BIP-39' : 'Invalid BIP-39'}
              </Badge>
              {seedValidation.error && (
                <span className="text-sm text-destructive">{seedValidation.error}</span>
              )}
            </div>
            {seedPhrase && !seedValidation.valid && (
              <div className="p-3 bg-amber-50 dark:bg-amber-950/20 rounded-lg border border-amber-200 dark:border-amber-800">
                <div className="text-sm text-amber-800 dark:text-amber-200">
                  <p className="font-medium mb-1">⚠️ Wallet Compatibility Note</p>
                  <p>
                    Many wallets will accept invalid seed phrases but display a warning. 
                    Seeds can still be generated and used, but may not be compatible across all wallet implementations.
                  </p>
                </div>
              </div>
            )}
          </div>

          {seedPhrase && (
            <div className="space-y-4">
              <Separator />
              
              {/* Word Analysis */}
              <div className="p-4 bg-blue-50 dark:bg-blue-950/20 rounded-lg border border-blue-200 dark:border-blue-800">
                <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">Phrase Analysis</h4>
                <div className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                  <div>Word count: {seedPhrase.trim().split(/\s+/).length}</div>
                  <div>Language: English (BIP-39 standard)</div>
                  <div>Entropy: {(seedPhrase.trim().split(/\s+/).length * 10.6667).toFixed(2)} bits (approximate)</div>
                  <div>Checksum: {seedValidation.valid ? 'Valid' : 'Invalid or missing'}</div>
                </div>
              </div>
            </div>
          )}

          {/* Master Seed and Keys */}
          {seedPhrase && (seedValidation.valid || (!seedValidation.valid && seedPhrase.trim().split(/\s+/).length >= 12)) && (
            <div className="space-y-4">
              <Separator />
              <div className="flex items-center gap-2">
                <h4 className="font-semibold text-lg">Extended Master Keys</h4>
                {!seedValidation.valid && (
                  <Badge variant="outline" className="text-xs">
                    Generated from invalid phrase
                  </Badge>
                )}
              </div>
              
              <div className="space-y-4">
                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Master Seed (512-bit)</Label>
                  <div className="flex gap-2">
                    <code className="flex-1 p-3 bg-muted rounded font-mono text-xs break-all">
                      {masterSeed}
                    </code>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => copyToClipboard(masterSeed)}
                      title="Copy"
                    >
                      <Copy size={16} />
                    </Button>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    Generated from mnemonic using PBKDF2 with 2048 iterations
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="space-y-3">
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Master Keys (xpriv/xpub)</Label>
                    <div className="space-y-2">
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-xs break-all border border-accent/20">
                          {xpriv}
                        </code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(xpriv)}
                          title="Copy xpriv"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-xs break-all border border-accent/20">
                          {xpub}
                        </code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(xpub)}
                          title="Copy xpub"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground">Master Extended Keys</div>
                    <div className="flex justify-center mt-2">
                      <QRCodeDisplay 
                        value={xpriv} 
                        title="Master xpriv" 
                        size={120}
                      />
                    </div>
                  </div>

                  <div className="space-y-3">
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Segwit (ypriv/ypub)</Label>
                    <div className="space-y-2">
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-xs break-all border border-accent/20">
                          {ypriv}
                        </code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(ypriv)}
                          title="Copy ypriv"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-xs break-all border border-accent/20">
                          {ypub}
                        </code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(ypub)}
                          title="Copy ypub"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground">P2SH-P2WPKH (Segwit)</div>
                    <div className="flex justify-center mt-2">
                      <QRCodeDisplay 
                        value={ypriv} 
                        title="Segwit ypriv" 
                        size={120}
                      />
                    </div>
                  </div>

                  <div className="space-y-3">
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Native Segwit (zpriv/zpub)</Label>
                    <div className="space-y-2">
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-xs break-all border border-accent/20">
                          {zpriv}
                        </code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(zpriv)}
                          title="Copy zpriv"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-xs break-all border border-accent/20">
                          {zpub}
                        </code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(zpub)}
                          title="Copy zpub"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground">P2WPKH (Native Segwit)</div>
                    <div className="flex justify-center mt-2">
                      <QRCodeDisplay 
                        value={zpriv} 
                        title="Native Segwit zpriv" 
                        size={120}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* HD Key Derivation */}
          {seedPhrase && (seedValidation.valid || (!seedValidation.valid && seedPhrase.trim().split(/\s+/).length >= 12)) && derivedKeys.length > 0 && (
            <div className="space-y-4">
              <Separator />
              <h4 className="font-semibold text-lg">Hierarchical Deterministic Key Derivation</h4>
              
              <div className="space-y-2">
                <Label htmlFor="derivation-path">Derivation Path</Label>
                <Input
                  id="derivation-path"
                  value={derivationPath}
                  onChange={(e) => setDerivationPath(e.target.value)}
                  placeholder="m/86'/0'/0'"
                  className="font-mono text-sm"
                />
                <div className="text-xs text-muted-foreground">
                  BIP-44 standard: m/purpose'/coin_type'/account' (change and address_index will be added automatically)
                </div>
              </div>

              {/* Derivation Path Summary */}
              <div className="p-4 bg-blue-50 dark:bg-blue-950/20 rounded-lg border border-blue-200 dark:border-blue-800">
                <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">Standard Derivation Paths</h4>
                <div className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                  <div><strong>Legacy (P2PKH):</strong> m/44'/0'/0' - Traditional Bitcoin addresses starting with "1"</div>
                  <div><strong>Segwit (P2SH):</strong> m/49'/0'/0' - Segwit wrapped in P2SH addresses starting with "3"</div>
                  <div><strong>Native Segwit (P2WPKH):</strong> m/84'/0'/0' - Bech32 addresses starting with "bc1q"</div>
                  <div><strong>Taproot (P2TR):</strong> m/86'/0'/0' - Taproot addresses starting with "bc1p"</div>
                </div>
              </div>

              <div className="space-y-3">
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Derived Keys (First 5 addresses)</Label>
                
                {derivedKeys.map((key, index) => (
                  <div key={index} className="p-4 bg-muted rounded-lg">
                    <div className="flex items-center gap-2 mb-3">
                      <Key size={16} className="text-accent" />
                      <code className="text-sm font-medium">{key.path}</code>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Private Key</Label>
                        <div className="flex gap-2">
                          <code className="flex-1 p-2 bg-background rounded font-mono text-xs break-all">
                            {key.privateKey}
                          </code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(key.privateKey)}
                            title="Copy"
                          >
                            <Copy size={12} />
                          </Button>
                        </div>
                        <div className="flex justify-center mt-2">
                          <QRCodeDisplay 
                            value={key.privateKey} 
                            title={`Private Key ${index + 1}`} 
                            size={100}
                          />
                        </div>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-xs text-muted-foreground">Address</Label>
                        <div className="flex gap-2">
                          <code className="flex-1 p-2 bg-background rounded font-mono text-xs">
                            {key.address}
                          </code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(key.address)}
                            title="Copy"
                          >
                            <Copy size={12} />
                          </Button>
                        </div>
                        <div className="flex justify-center mt-2">
                          <QRCodeDisplay 
                            value={key.address} 
                            title={`Address ${index + 1}`} 
                            size={100}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Information Box */}
          <div className="p-4 bg-amber-50 dark:bg-amber-950/20 rounded-lg border border-amber-200 dark:border-amber-800">
            <h4 className="font-semibold text-amber-900 dark:text-amber-100 mb-2">About BIP-39 and HD Wallets</h4>
            <div className="text-sm text-amber-800 dark:text-amber-200 space-y-2">
              <p>
                <strong>BIP-39</strong> defines how mnemonic phrases are generated and converted to binary seeds. 
                The seed is created from the seed phrase text using PBKDF2 with 2048 iterations and an optional passphrase.
              </p>
              <p>
                <strong>Wallet Compatibility:</strong> Note that the seed phrase does not have to be a valid BIP-39 seed phrase - any text can be used as input.
                Many wallets accept invalid seed phrases but will display a warning. 
                While seeds can be generated from any input, using non-standard phrases may result in compatibility 
                issues between different wallet implementations.
              </p>
              <p>
                <strong>BIP-32</strong> defines hierarchical deterministic (HD) wallet structure, allowing generation 
                of a tree of key pairs from a single master seed.
              </p>
              <p>
                <strong>BIP-44</strong> defines the standard derivation path structure: 
                m/purpose'/coin_type'/account'/change/address_index, where Bitcoin uses coin_type = 0.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}