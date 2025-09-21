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
import { 
  privateKeyFromHex as importedPrivateKeyFromHex
} from '@/lib/bitcoin'
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

  // Generate derived keys function
  const generateDerivedKeys = (basePath: string, masterNode: any) => {
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
        const keyData = importedPrivateKeyFromHex(privateKeyHex)
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
      try {
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
        generateDerivedKeys(derivationPath || "m/86'/0'/0'", masterNode)
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
  }, [seedPhrase, derivationPath])

  const generateRandomSeed = () => {
    const wordCount = parseInt(selectedWordCount || '12')
    const strength = ((wordCount - 12) / 3) * 32 + 128 // 128, 160, 192, 224, 256 bits
    const mnemonic = bip39.generateMnemonic(strength)
    setSeedPhrase(mnemonic)
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(console.error)
    }
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
          </div>

          {seedPhrase && (
            <div className="space-y-4">
              <Separator />
              <div className="space-y-2">
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Validation Result</Label>
                <div className="flex items-center gap-2">
                  <Badge variant={seedValidation.valid ? "default" : "destructive"}>
                    {seedValidation.valid ? 'Valid BIP-39' : 'Invalid BIP-39'}
                  </Badge>
                  {seedValidation.error && (
                    <span className="text-sm text-destructive">{seedValidation.error}</span>
                  )}
                </div>
              </div>

              {!seedValidation.valid && (
                <div className="p-3 bg-muted rounded text-sm">
                  <strong>Wallet Compatibility:</strong> Note that the seed phrase does not have to be a valid BIP-39 seed phrase - any text can be used as input. Many wallets accept invalid seed phrases but will display a warning.
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Seed Analysis */}
      {seedPhrase && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ArrowRight className="text-accent" />
              Phrase Analysis
            </CardTitle>
            <CardDescription>
              Detailed analysis of the entered seed phrase
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Word Count</Label>
                <div className="text-sm font-mono">{seedPhrase.trim().split(/\s+/).length} words</div>
              </div>
              <div>
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Entropy</Label>
                <div className="text-sm font-mono">
                  {Math.round((seedPhrase.trim().split(/\s+/).length * Math.log2(2048)) * 100) / 100} bits
                </div>
              </div>
              <div>
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Security Level</Label>
                <div className="text-sm">
                  {(() => {
                    const words = seedPhrase.trim().split(/\s+/).length
                    if (words >= 24) return "Very High"
                    if (words >= 18) return "High"
                    if (words >= 15) return "Medium"
                    if (words >= 12) return "Standard"
                    return "Low"
                  })()}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Master Seed and Keys */}
      {masterSeed && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="text-accent" />
              Master Seed and Keys
            </CardTitle>
            <CardDescription>
              Master seed and extended public/private key pairs derived from the mnemonic
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div>
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Master Seed (Hex)</Label>
                <div className="flex gap-2">
                  <code className="flex-1 p-3 bg-muted rounded font-mono text-xs break-all">{masterSeed}</code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(masterSeed)}
                    title="Copy"
                  >
                    <Copy size={16} />
                  </Button>
                </div>
              </div>

              <Separator />
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h4 className="font-semibold">Extended Private Keys</h4>
                  
                  <div className="flex gap-4 items-start">
                    <div className="flex-1">
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">xpriv (BIP44/Legacy)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">{xpriv}</code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(xpriv)}
                          title="Copy"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <QRCodeDisplay 
                      value={xpriv} 
                      title="xpriv" 
                      size={100}
                    />
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-1">
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">ypriv (BIP49/SegWit)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">{ypriv}</code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(ypriv)}
                          title="Copy"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <QRCodeDisplay 
                      value={ypriv} 
                      title="ypriv" 
                      size={100}
                    />
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-1">
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">zpriv (BIP84/Native SegWit)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">{zpriv}</code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(zpriv)}
                          title="Copy"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <QRCodeDisplay 
                      value={zpriv} 
                      title="zpriv" 
                      size={100}
                    />
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-semibold">Extended Public Keys</h4>
                  
                  <div className="flex gap-4 items-start">
                    <div className="flex-1">
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">xpub (BIP44/Legacy)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">{xpub}</code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(xpub)}
                          title="Copy"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <QRCodeDisplay 
                      value={xpub} 
                      title="xpub" 
                      size={100}
                    />
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-1">
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">ypub (BIP49/SegWit)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">{ypub}</code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(ypub)}
                          title="Copy"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <QRCodeDisplay 
                      value={ypub} 
                      title="ypub" 
                      size={100}
                    />
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-1">
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">zpub (BIP84/Native SegWit)</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">{zpub}</code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(zpub)}
                          title="Copy"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                    <QRCodeDisplay 
                      value={zpub} 
                      title="zpub" 
                      size={100}
                    />
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Hierarchical Deterministic Key Derivation */}
      {masterSeed && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ArrowRight className="text-accent" />
              Hierarchical Deterministic Key Derivation
            </CardTitle>
            <CardDescription>
              Generate child keys using BIP-32 derivation paths. Enter a path up to the account level (m/purpose'/coin_type'/account').
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div>
                <Label htmlFor="derivation-path">Derivation Path (up to account level)</Label>
                <Input
                  id="derivation-path"
                  value={derivationPath}
                  onChange={(e) => setDerivationPath(e.target.value)}
                  placeholder="m/86'/0'/0'"
                  className="font-mono"
                />
              </div>

              <div className="p-4 bg-muted rounded space-y-2">
                <h4 className="font-semibold text-sm">Common Derivation Paths:</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                  <div><code>m/44'/0'/0'</code> - Legacy (P2PKH)</div>
                  <div><code>m/49'/0'/0'</code> - SegWit (P2SH-P2WPKH)</div>
                  <div><code>m/84'/0'/0'</code> - Native SegWit (P2WPKH)</div>
                  <div><code>m/86'/0'/0'</code> - Taproot (P2TR)</div>
                </div>
              </div>
            </div>

            {derivedKeys.length > 0 && (
              <div className="space-y-4">
                <Separator />
                <h4 className="font-semibold">Derived Keys (First 5 addresses, change branch 0)</h4>
                <div className="space-y-3">
                  {derivedKeys.map((key, index) => (
                    <div key={index} className="p-4 border rounded space-y-2">
                      <div className="flex justify-between items-center">
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">
                          Path: {key.path}
                        </Label>
                      </div>
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <div>
                          <Label className="text-xs uppercase tracking-wide text-muted-foreground">Private Key</Label>
                          <div className="flex gap-2">
                            <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">
                              {key.privateKey}
                            </code>
                            <Button
                              variant="outline"
                              size="icon"
                              onClick={() => copyToClipboard(key.privateKey)}
                              title="Copy"
                            >
                              <Copy size={16} />
                            </Button>
                          </div>
                        </div>
                        <div>
                          <Label className="text-xs uppercase tracking-wide text-muted-foreground">Address</Label>
                          <div className="flex gap-2">
                            <code className="flex-1 p-2 bg-muted rounded font-mono text-xs break-all">
                              {key.address}
                            </code>
                            <Button
                              variant="outline"
                              size="icon"
                              onClick={() => copyToClipboard(key.address)}
                              title="Copy"
                            >
                              <Copy size={16} />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* About Section */}
      <Card>
        <CardHeader>
          <CardTitle>About BIP-39 and HD Wallets</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <h4 className="font-semibold">BIP-39 (Mnemonic Seeds)</h4>
            <p className="text-sm text-muted-foreground">
              BIP-39 defines how to generate mnemonic sentences (seed phrases) that can be used to derive cryptographic keys. 
              The seed is created from the seed phrase text and is used as the root for hierarchical deterministic wallets.
            </p>
          </div>
          
          <div className="space-y-2">
            <h4 className="font-semibold">BIP-32 (Hierarchical Deterministic Wallets)</h4>
            <p className="text-sm text-muted-foreground">
              BIP-32 enables the generation of multiple keys from a single seed. This allows users to generate many addresses 
              from one backup, improving privacy and usability. Keys are derived using mathematical functions, 
              ensuring deterministic and reproducible wallet generation.
            </p>
          </div>

          <div className="space-y-2">
            <h4 className="font-semibold">Derivation Paths</h4>
            <p className="text-sm text-muted-foreground">
              Different Bitcoin address types use different derivation paths. Legacy addresses use BIP-44 (m/44'), 
              SegWit addresses use BIP-49 (m/49'), Native SegWit uses BIP-84 (m/84'), and Taproot uses BIP-86 (m/86').
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}