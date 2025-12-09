import { useState, useEffect } from 'react'
import { useKV } from '@github/spark/hooks'
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
  // Persistent inputs using useKV
  const [miniKeyInput, setMiniKeyInput] = useKV('mini-key-input', '')
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
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold mb-2">Mini Key</h2>
        <p className="text-muted-foreground">
          Demonstrates Bitcoin mini private key generation, validation and key derivation.
        </p>
      </div>

      {/* Mini Key Generation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkle className="text-accent" />
            Mini Key Generation
          </CardTitle>
          <CardDescription>
            Generate a valid 30-character Bitcoin mini key that passes all validation checks
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="text-center">
              <Button
                onClick={generateRandom}
                className="w-full"
                size="lg"
              >
                <Sparkle className="mr-2" size={16} />
                Generate Random Mini Key
              </Button>
              <div className="text-xs text-muted-foreground mt-2">
                Creates a cryptographically valid mini key and populates the derivation section below
              </div>
            </div>

            {miniKeyInput && (
              <div className="space-y-2">
                <Label className="text-xs uppercase tracking-wide text-muted-foreground">Generated Mini Key</Label>
                <div className="flex gap-4 items-start">
                  <div className="flex-1 space-y-2">
                    <div className="flex gap-2">
                      <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                        {miniKeyInput}
                      </code>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => copyToClipboard(miniKeyInput)}
                        title="Copy"
                      >
                        <Copy size={16} />
                      </Button>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      This mini key has been automatically populated in the derivation section below
                    </div>
                  </div>
                  <QRCodeDisplay 
                    value={miniKeyInput} 
                    title="Mini Key" 
                    size={100}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Information Box */}
          <div className="p-4 bg-blue-50 dark:bg-blue-950/20 rounded-lg border border-blue-200 dark:border-blue-800">
            <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">Mini Key Format Requirements</h4>
            <div className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
              <div className="flex items-center gap-2">
                <span>•</span>
                <span>Exactly 30 characters long</span>
              </div>
              <div className="flex items-center gap-2">
                <span>•</span>
                <span>Must start with the character 'S'</span>
              </div>
              <div className="flex items-center gap-2">
                <span>•</span>
                <span>All characters must be from the Base58 alphabet</span>
              </div>
              <div className="flex items-center gap-2">
                <span>•</span>
                <span>Must pass cryptographic check: SHA256(minikey + '?') first byte = 0</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Mini Key Derivation Section */}
      {/* Mini Key Derivation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            Mini Key Private Key Derivation
          </CardTitle>
          <CardDescription>
            Enter or use the generated mini key above to derive the private key
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="mini-key-input">Mini Key</Label>
            <div className="flex gap-2">
              <Input
                id="mini-key-input"
                value={miniKeyInput}
                onChange={(e) => setMiniKeyInput(e.target.value)}
                placeholder="30-character mini key starting with 'S' (or use generator above)"
                className="font-mono text-sm"
                maxLength={30}
              />
              <Button
                variant="outline"
                size="icon"
                onClick={generateRandom}
                title="Generate Random"
              >
                <Shuffle size={16} />
              </Button>
            </div>
            <div className="text-xs text-muted-foreground">
              Mini keys are exactly 30 characters long and start with 'S'. Use the generator above or enter manually.
            </div>
          </div>

          {/* Validation Status */}
          <div className="space-y-2">
            <Label className="text-xs uppercase tracking-wide text-muted-foreground">Validation Status</Label>
            <div className="flex items-center gap-2">
              <Badge variant={validation.valid ? "default" : miniKeyInput ? "destructive" : "secondary"}>
                {!miniKeyInput ? 'No Input' : validation.valid ? 'Valid' : 'Invalid'}
              </Badge>
              {validation.error && (
                <span className="text-sm text-destructive">{validation.error}</span>
              )}
            </div>
          </div>

          {miniKeyInput && (
            <div className="space-y-4">
              <Separator />
              
              {/* Validation Details */}
              <div className="p-4 bg-blue-50 dark:bg-blue-950/20 rounded-lg border border-blue-200 dark:border-blue-800">
                <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">Mini Key Validation Rules</h4>
                <div className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                  <div className={`flex items-center gap-2 ${miniKeyInput.length === 30 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                    <span>{miniKeyInput.length === 30 ? '✓' : '✗'}</span>
                    <span>Length: {miniKeyInput.length}/30 characters</span>
                  </div>
                  <div className={`flex items-center gap-2 ${miniKeyInput.startsWith('S') ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                    <span>{miniKeyInput.startsWith('S') ? '✓' : '✗'}</span>
                    <span>Starts with 'S': {miniKeyInput.charAt(0) || 'N/A'}</span>
                  </div>
                  <div className={`flex items-center gap-2 ${/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$/.test(miniKeyInput) ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                    <span>{/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$/.test(miniKeyInput) ? '✓' : '✗'}</span>
                    <span>Base58 characters only</span>
                  </div>
                  <div className={`flex items-center gap-2 ${validation.valid ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                    <span>{validation.valid ? '✓' : '✗'}</span>
                    <span>Cryptographic check: SHA256(minikey + '?') first byte = 0</span>
                  </div>
                </div>
              </div>

              {/* Derived Private Key */}
              {derivedData && validation.valid && (
                <div className="space-y-4">
                  <Separator />
                  <h4 className="font-semibold text-lg">Derived Private Key</h4>
                  
                  <div className="space-y-4">
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Mini Key Input</Label>
                      <div className="flex gap-2">
                        <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                          {miniKeyInput}
                        </code>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => copyToClipboard(miniKeyInput)}
                          title="Copy"
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">30-character compact private key format</div>
                    </div>

                    {/* Private Key Derivation Process */}
                    <div className="p-4 bg-slate-50 dark:bg-slate-950/50 rounded-lg border">
                      <h5 className="font-semibold text-sm mb-3">Private Key Derivation Process</h5>
                      <div className="space-y-3 text-sm">
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-xs bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded">Step 1</span>
                          <span>Take the mini key: <code className="font-mono bg-muted px-1 py-0.5 rounded text-xs">{miniKeyInput}</code></span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-xs bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded">Step 2</span>
                          <span>Apply SHA256 hash function</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-xs bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded">Step 3</span>
                          <span>Result is the 32-byte private key in hexadecimal format</span>
                        </div>
                      </div>
                    </div>

                    <div className="text-center text-muted-foreground">
                      <ArrowRight className="mx-auto" size={20} />
                      <div className="text-xs mt-1">SHA256(mini_key)</div>
                    </div>

                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">Private Key (Hex)</Label>
                      <div className="flex gap-4 items-start">
                        <div className="flex-1 space-y-2">
                          <div className="flex gap-2">
                            <code className="flex-1 p-3 bg-muted rounded font-mono text-sm break-all">
                              {derivedData.privateKeyHex}
                            </code>
                            <Button
                              variant="outline"
                              size="icon"
                              onClick={() => copyToClipboard(derivedData.privateKeyHex || '')}
                              title="Copy"
                            >
                              <Copy size={16} />
                            </Button>
                          </div>
                          <div className="text-xs text-muted-foreground">32-byte private key derived from mini key</div>
                        </div>
                        <QRCodeDisplay 
                          value={derivedData.privateKeyHex || ''} 
                          title="Private Key" 
                          size={100}
                        />
                      </div>
                    </div>

                    {/* WIF Formats */}
                    <div>
                      <Label className="text-xs uppercase tracking-wide text-muted-foreground">WIF Formats</Label>
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        {/* Compressed WIF */}
                        <div className="space-y-2">
                          <Label className="text-xs text-muted-foreground">Compressed WIF</Label>
                          <div className="flex gap-4 items-start">
                            <div className="flex-1">
                              <div className="flex gap-2">
                                <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                                  {derivedData.privateKeyWif}
                                </code>
                                <Button
                                  variant="outline"
                                  size="icon"
                                  onClick={() => copyToClipboard(derivedData.privateKeyWif || '')}
                                  title="Copy"
                                >
                                  <Copy size={16} />
                                </Button>
                              </div>
                            </div>
                            <QRCodeDisplay 
                              value={derivedData.privateKeyWif || ''} 
                              title="Compressed WIF" 
                              size={80}
                            />
                          </div>
                        </div>

                        {/* Uncompressed WIF */}
                        <div className="space-y-2">
                          <Label className="text-xs text-muted-foreground">Uncompressed WIF</Label>
                          <div className="flex gap-4 items-start">
                            <div className="flex-1">
                              <div className="flex gap-2">
                                <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                                  {uncompressedWif}
                                </code>
                                <Button
                                  variant="outline"
                                  size="icon"
                                  onClick={() => copyToClipboard(uncompressedWif)}
                                  title="Copy"
                                >
                                  <Copy size={16} />
                                </Button>
                              </div>
                            </div>
                            <QRCodeDisplay 
                              value={uncompressedWif} 
                              title="Uncompressed WIF" 
                              size={80}
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Information Box */}
          <div className="p-4 bg-amber-50 dark:bg-amber-950/20 rounded-lg border border-amber-200 dark:border-amber-800">
            <h4 className="font-semibold text-amber-900 dark:text-amber-100 mb-2">About Bitcoin Mini Keys</h4>
            <div className="text-sm text-amber-800 dark:text-amber-200 space-y-2">
              <p>
                Mini keys are a compact way to represent Bitcoin private keys, historically used by some applications 
                like Casascius physical bitcoins. They are 30 characters long and start with 'S'.
              </p>
              <p>
                The format includes a built-in check: SHA256(minikey + '?') must have a first byte of 0x00. 
                This provides roughly 99.6% rejection of invalid strings.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}