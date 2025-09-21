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
  validatePublicKey,
  BitcoinKeyData 
} from '@/lib/bitcoin-lite'

export function PublicKeyPage() {
  // Persistent inputs using useKV
  const [wifInput, setWifInput] = useKV('public-key-wif-input', '')
  const [publicKeyInput, setPublicKeyInput] = useKV('public-key-validation-input', '')
  
  const [derivedData, setDerivedData] = useState<BitcoinKeyData | null>(null)
  const [validation, setValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })
  
  // Get shared compressed WIF from Private Key page
  const [sharedCompressedWif] = useKV('shared-compressed-wif', '')
  
  // Initialize WIF input with shared compressed WIF on first load
  useEffect(() => {
    if (sharedCompressedWif && !wifInput) {
      setWifInput(sharedCompressedWif)
    }
  }, [sharedCompressedWif, wifInput])

  // Handle WIF input for derivation
  useEffect(() => {
    const processWif = async () => {
      if (wifInput) {
        const data = await privateKeyFromWif(wifInput)
        setDerivedData(data)
        
        // Auto-populate validation input with derived public key
        if (data?.publicKeyHex && !publicKeyInput) {
          setPublicKeyInput(data.publicKeyHex)
        }
      } else {
        setDerivedData(null)
      }
    }
    
    processWif()
  }, [wifInput, publicKeyInput])

  // Update validation input when derived data changes
  useEffect(() => {
    if (derivedData?.publicKeyHex && !publicKeyInput) {
      setPublicKeyInput(derivedData.publicKeyHex)
    }
  }, [derivedData, publicKeyInput, setPublicKeyInput])

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
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(console.error)
    }
  }

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold mb-2">Public Key</h2>
        <p className="text-muted-foreground">
          Derive public keys from private keys and validate public key formats.
        </p>
      </div>

      {/* Derivation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            Public Key Derivation
          </CardTitle>
          <CardDescription>
            Derive a public key from a private key in WIF format
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="wif-derivation">Private Key (WIF)</Label>
            <div className="flex gap-2">
              <Input
                id="wif-derivation"
                value={wifInput}
                onChange={(e) => setWifInput(e.target.value)}
                placeholder="Enter WIF format private key"
                className="font-mono text-sm"
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
          </div>

          {derivedData && (
            <div className="space-y-4">
              <Separator />
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Private Key (Hex)</Label>
                    <div className="flex gap-2">
                      <code className="flex-1 p-2 bg-muted rounded font-mono text-sm break-all">
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
                  </div>

                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Compression Flag</Label>
                    <div className="flex items-center gap-2">
                      <Badge variant={derivedData.compressed ? "default" : "secondary"}>
                        {derivedData.compressed ? 'Compressed' : 'Uncompressed'}
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        {derivedData.compressed ? 'Public key is 33 bytes (66 hex chars)' : 'Public key is 65 bytes (130 hex chars)'}
                      </span>
                    </div>
                  </div>
                </div>

                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Derived Public Key</Label>
                  <div className="flex gap-2">
                    <code className="flex-1 p-2 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                      {derivedData.publicKeyHex}
                    </code>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => copyToClipboard(derivedData.publicKeyHex || '')}
                      title="Copy"
                    >
                      <Copy size={16} />
                    </Button>
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">
                    {derivedData.compressed 
                      ? `Starts with ${derivedData.publicKeyHex?.slice(0, 2)} (compressed prefix)`
                      : 'Starts with 04 (uncompressed prefix)'
                    }
                  </div>
                </div>
              </div>

              <div className="p-4 bg-blue-50 dark:bg-blue-950/20 rounded-lg border border-blue-200 dark:border-blue-800">
                <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">Derivation Process</h4>
                <div className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                  <div>1. Private key → ECDSA point multiplication with generator point G</div>
                  <div>2. {derivedData.compressed ? 'Compressed format: Include only x-coordinate + prefix (02/03)' : 'Uncompressed format: Include both x and y coordinates + prefix (04)'}</div>
                  <div>3. Result: {derivedData.compressed ? '33-byte' : '65-byte'} public key</div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Validation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            Public Key Validation
          </CardTitle>
          <CardDescription>
            Validate a public key in hexadecimal format
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="pubkey-validation">Public Key (Hex)</Label>
            <Input
              id="pubkey-validation"
              value={publicKeyInput}
              onChange={(e) => setPublicKeyInput(e.target.value)}
              placeholder="Enter public key in hexadecimal format"
              className="font-mono text-sm"
            />
          </div>

          {publicKeyInput && (
            <div className="space-y-4">
              <Separator />
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Validation Result</Label>
                  <div className="flex items-center gap-2">
                    <Badge variant={validation.valid ? "default" : "destructive"}>
                      {validation.valid ? 'Valid' : 'Invalid'}
                    </Badge>
                    {validation.error && (
                      <span className="text-sm text-destructive">{validation.error}</span>
                    )}
                  </div>
                </div>

                {validation.valid && (
                  <div>
                    <Label className="text-xs uppercase tracking-wide text-muted-foreground">Format Details</Label>
                    <div className="space-y-1">
                      <div className="text-sm">
                        <span className="font-medium">Length:</span> {publicKeyInput.length} characters ({publicKeyInput.length / 2} bytes)
                      </div>
                      <div className="text-sm">
                        <span className="font-medium">Type:</span> {
                          publicKeyInput.length === 66 ? 'Compressed' : 
                          publicKeyInput.length === 130 ? 'Uncompressed' : 'Unknown'
                        }
                      </div>
                      <div className="text-sm">
                        <span className="font-medium">Prefix:</span> {publicKeyInput.slice(0, 2)}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="p-4 bg-amber-50 dark:bg-amber-950/20 rounded-lg border border-amber-200 dark:border-amber-800">
                <h4 className="font-semibold text-amber-900 dark:text-amber-100 mb-2">Validation Checks</h4>
                <div className="text-sm text-amber-800 dark:text-amber-200 space-y-1">
                  <div>• Hexadecimal characters only (0-9, A-F)</div>
                  <div>• Valid prefix: 02/03 (compressed) or 04 (uncompressed)</div>
                  <div>• Correct length: 66 chars (compressed) or 130 chars (uncompressed)</div>
                  <div>• Point lies on the secp256k1 elliptic curve</div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}