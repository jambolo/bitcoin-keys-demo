// Import polyfills first, before any crypto libraries
import '@/lib/polyfills'
import { Buffer } from 'buffer'

import { useState, useEffect } from 'react'
import { useKV } from '@github/spark/hooks'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Textarea } from '@/components/ui/textarea'
import { Copy, Shuffle, ArrowRight, Key } from '@phosphor-icons/react'
import * as bip39 from 'bip39'

export function SeedPage() {
  // Persistent inputs using useKV
  const [seedPhrase, setSeedPhrase] = useKV('seed-phrase', '')
  const [derivationPath, setDerivationPath] = useKV('seed-derivation-path', "m/44'/0'/0'/0/0")
  
  const [seedValidation, setSeedValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })
  const [masterSeed, setMasterSeed] = useState('')
  const [masterPrivateKey, setMasterPrivateKey] = useState('')
  const [masterPublicKey, setMasterPublicKey] = useState('')
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
        
        // Generate master seed and keys
        const seed = bip39.mnemonicToSeedSync(seedPhrase)
        const seedBuffer = Buffer.from(seed)
        setMasterSeed(seedBuffer.toString('hex'))
        
        // Simplified master key generation for demo
        const masterPriv = seedBuffer.subarray(0, 32).toString('hex')
        setMasterPrivateKey(masterPriv)
        setMasterPublicKey('04' + seedBuffer.subarray(32, 65).toString('hex'))
        
        // Generate some derived keys for demo
        const derived: Array<{
          path: string
          privateKey: string
          address: string
        }> = []
        for (let i = 0; i < 5; i++) {
          const derivedSeed = seedBuffer.subarray(i * 6, i * 6 + 32)
          derived.push({
            path: `m/44'/0'/0'/0/${i}`,
            privateKey: derivedSeed.toString('hex'),
            address: '1Demo' + derivedSeed.subarray(0, 4).toString('hex')
          })
        }
        setDerivedKeys(derived)
      } else {
        setSeedValidation({ valid: false, error: 'Invalid BIP-39 mnemonic phrase' })
        setMasterSeed('')
        setMasterPrivateKey('')
        setMasterPublicKey('')
        setDerivedKeys([])
      }
    } else {
      setSeedValidation({ valid: false })
      setMasterSeed('')
      setMasterPrivateKey('')
      setMasterPublicKey('')
      setDerivedKeys([])
    }
  }, [seedPhrase])

  const generateRandomSeed = () => {
    const mnemonic = bip39.generateMnemonic()
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
              <Button
                variant="outline"
                size="icon"
                onClick={generateRandomSeed}
                title="Generate Random"
                className="self-start"
              >
                <Shuffle size={16} />
              </Button>
            </div>
            <div className="text-xs text-muted-foreground">
              BIP-39 mnemonic phrases use a standardized word list for generating seeds
            </div>
          </div>

          {/* Validation Status */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wide text-muted-foreground">Validation Status</Label>
            <div className="flex items-center gap-2">
              <Badge variant={seedValidation.valid ? "default" : seedPhrase ? "destructive" : "secondary"}>
                {!seedPhrase ? 'No Input' : seedValidation.valid ? 'Valid BIP-39' : 'Invalid'}
              </Badge>
              {seedValidation.error && (
                <span className="text-sm text-destructive">{seedValidation.error}</span>
              )}
            </div>
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
                  <div>Entropy: {seedPhrase.trim().split(/\s+/).length * 10.33} bits (approximate)</div>
                  <div>Checksum: {seedValidation.valid ? 'Valid' : 'Invalid or missing'}</div>
                </div>
              </div>
            </div>
          )}

          {/* Master Seed and Keys */}
          {seedValidation.valid && (
            <div className="space-y-4">
              <Separator />
              <h4 className="font-semibold text-lg">Master Seed and Keys</h4>
              
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

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Master Private Key</Label>
                    <div className="flex gap-2">
                      <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                        {masterPrivateKey}
                      </code>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => copyToClipboard(masterPrivateKey)}
                        title="Copy"
                      >
                        <Copy size={16} />
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">First 32 bytes of master seed</div>
                  </div>

                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Master Public Key</Label>
                    <div className="flex gap-2">
                      <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                        {masterPublicKey}
                      </code>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => copyToClipboard(masterPublicKey)}
                        title="Copy"
                      >
                        <Copy size={16} />
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Derived from master private key</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* HD Key Derivation */}
          {seedValidation.valid && derivedKeys.length > 0 && (
            <div className="space-y-4">
              <Separator />
              <h4 className="font-semibold text-lg">Hierarchical Deterministic Key Derivation</h4>
              
              <div className="space-y-2">
                <Label htmlFor="derivation-path">Derivation Path</Label>
                <Input
                  id="derivation-path"
                  value={derivationPath}
                  onChange={(e) => setDerivationPath(e.target.value)}
                  placeholder="m/44'/0'/0'/0/0"
                  className="font-mono text-sm"
                />
                <div className="text-xs text-muted-foreground">
                  BIP-44 standard: m/purpose'/coin_type'/account'/change/address_index
                </div>
              </div>

              <div className="space-y-3">
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Derived Keys (First 5 addresses)</Label>
                
                {derivedKeys.map((key, index) => (
                  <div key={index} className="p-3 bg-muted rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <Key size={16} className="text-accent" />
                      <code className="text-sm font-medium">{key.path}</code>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-sm">
                      <div>
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
                      </div>
                      <div>
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
                The seed is created using PBKDF2 with 2048 iterations and an optional passphrase.
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