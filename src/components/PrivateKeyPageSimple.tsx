import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { QRCode } from '@/components/QRCode'
import { Copy } from '@phosphor-icons/react'
import { toast } from 'sonner'
import { 
  generateRandomPrivateKey, 
  generateWifSteps,
  decodeWif,
  validateWif,
  isValidHex
} from '@/lib/bitcoin-lite'
import { useKV } from '@github/spark/hooks'

export function PrivateKeyPage() {
  const [isLibReady, setIsLibReady] = useState(false)
  const [initError, setInitError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  
  // Persistent state for inputs
  const [privateKeyHex, setPrivateKeyHex] = useKV("private-key-hex", "")
  const [wifInput, setWifInput] = useKV("wif-input", "")
  const [wifValidationInput, setWifValidationInput] = useKV("wif-validation-input", "")

  useEffect(() => {
    const initLib = async () => {
      try {
        console.log('Bitcoin library ready (no initialization needed)')
        setIsLibReady(true)
      } catch (error: any) {
        console.error('Bitcoin library error:', error)
        setInitError(error.message || 'Unknown error')
      } finally {
        setIsLoading(false)
      }
    }
    
    initLib()
  }, [])

  // Effect to sync compressed WIF to validation input when library is ready
  useEffect(() => {
    if (isLibReady && privateKeyHex && isValidHex(privateKeyHex, 64) && !wifValidationInput) {
      const compressedSteps = generateWifSteps(privateKeyHex, true)
      if (compressedSteps) {
        setWifValidationInput(compressedSteps.wif)
      }
    }
  }, [isLibReady, privateKeyHex, wifValidationInput, setWifValidationInput])

  const handleGenerateRandom = () => {
    try {
      const wif = generateRandomPrivateKey()
      setWifInput(wif)
      
      // Also decode to get hex
      const decoded = decodeWif(wif)
      if (decoded) {
        setPrivateKeyHex(decoded.privateKeyHex)
        // Generate compressed WIF for validation if the random key was uncompressed
        const compressedSteps = generateWifSteps(decoded.privateKeyHex, true)
        if (compressedSteps) {
          setWifValidationInput(compressedSteps.wif)
        }
      }
    } catch (error: any) {
      console.error('Failed to generate key:', error)
    }
  }

  // Calculate WIF encoding steps
  const uncompressedSteps = (privateKeyHex && isValidHex(privateKeyHex, 64)) ? generateWifSteps(privateKeyHex, false) : null
  const compressedSteps = (privateKeyHex && isValidHex(privateKeyHex, 64)) ? generateWifSteps(privateKeyHex, true) : null

  // Decode WIF
  const wifDecoded = wifInput ? decodeWif(wifInput) : null

  // Validate WIF
  const wifValidation = wifValidationInput ? validateWif(wifValidationInput) : { valid: false }

  const handlePrivateKeyChange = (value: string) => {
    setPrivateKeyHex(value)
    
    // If valid hex, generate WIF and update inputs
    if (isValidHex(value, 64)) {
      const compressedSteps = generateWifSteps(value, true)
      const uncompressedSteps = generateWifSteps(value, false)
      if (compressedSteps && uncompressedSteps) {
        setWifInput(compressedSteps.wif)
        // Always use compressed WIF as default for validation section
        setWifValidationInput(compressedSteps.wif)
      }
    } else {
      // Clear validation input if private key is invalid
      setWifValidationInput("")
    }
  }

  const handleWifInputChange = (value: string) => {
    setWifInput(value)
    
    // If valid WIF, decode and update hex
    const decoded = decodeWif(value)
    if (decoded && decoded.valid) {
      setPrivateKeyHex(decoded.privateKeyHex)
      // Always update validation input with the current WIF
      setWifValidationInput(value)
    }
  }

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success(`${label} copied to clipboard`)
    } catch (error) {
      toast.error('Failed to copy to clipboard')
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Private Key</CardTitle>
          </CardHeader>
          <CardContent>
            <p>Initializing Bitcoin library...</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!isLibReady) {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Private Key</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-red-600">Failed to initialize Bitcoin library</p>
            {initError && (
              <p className="text-red-500 mt-2 text-sm">Error: {initError}</p>
            )}
            <p className="text-muted-foreground mt-4 text-sm">
              This may be due to WebAssembly compatibility issues. Please try refreshing the page.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* WIF Encoding Section */}
      <Card>
        <CardHeader>
          <CardTitle>WIF Encoding</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="private-key-hex">Private Key (Hex)</Label>
            <div className="flex gap-2">
              <Input
                id="private-key-hex"
                value={privateKeyHex || ""}
                onChange={(e) => handlePrivateKeyChange(e.target.value)}
                placeholder="Enter 64-character hex private key"
                className="font-mono"
              />
              <Button onClick={handleGenerateRandom}>Random</Button>
            </div>
          </div>

          {privateKeyHex && isValidHex(privateKeyHex, 64) && (
            <div className="space-y-6">
              <div className="grid md:grid-cols-2 gap-6">
                {/* Uncompressed WIF */}
                <div className="space-y-3">
                  <h4 className="font-semibold">Uncompressed WIF Process</h4>
                  {uncompressedSteps && (
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="text-muted-foreground">Step 1:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          80 + {privateKeyHex} → {uncompressedSteps.step1}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Step 2:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          SHA256(SHA256()) → {uncompressedSteps.step2}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Step 3:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          checksum_first_4_bytes → {uncompressedSteps.step3}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Step 4:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          80 + {privateKeyHex} + {uncompressedSteps.step3} → Base58() → {uncompressedSteps.wif}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Compressed WIF */}
                <div className="space-y-3">
                  <h4 className="font-semibold">Compressed WIF Process</h4>
                  {compressedSteps && (
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="text-muted-foreground">Step 1:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          80 + {privateKeyHex} + 01 → {compressedSteps.step1}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Step 2:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          SHA256(SHA256()) → {compressedSteps.step2}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Step 3:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          checksum_first_4_bytes → {compressedSteps.step3}
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Step 4:</span>
                        <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                          80 + {privateKeyHex} + 01 + {compressedSteps.step3} → Base58() → {compressedSteps.wif}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Final Encoded WIF Keys */}
              <div className="space-y-4 mt-6">
                <h4 className="font-semibold">Final Encoded Private Keys</h4>
                <div className="grid md:grid-cols-2 gap-4">
                  {uncompressedSteps && (
                    <div className="space-y-2">
                      <Label>Uncompressed WIF</Label>
                      <div className="flex gap-2">
                        <Input
                          value={uncompressedSteps.wif}
                          readOnly
                          className="font-mono text-xs"
                        />
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => copyToClipboard(uncompressedSteps.wif, 'Uncompressed WIF')}
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                  )}
                  {compressedSteps && (
                    <div className="space-y-2">
                      <Label>Compressed WIF</Label>
                      <div className="flex gap-2">
                        <Input
                          value={compressedSteps.wif}
                          readOnly
                          className="font-mono text-xs"
                        />
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => copyToClipboard(compressedSteps.wif, 'Compressed WIF')}
                        >
                          <Copy size={16} />
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* QR Codes */}
              <div className="grid md:grid-cols-2 gap-6">
                {uncompressedSteps && (
                  <QRCode 
                    value={uncompressedSteps.wif} 
                    title="Uncompressed WIF"
                    size={128}
                  />
                )}
                {compressedSteps && (
                  <QRCode 
                    value={compressedSteps.wif} 
                    title="Compressed WIF"
                    size={128}
                  />
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* WIF Decoding Section */}
      <Card>
        <CardHeader>
          <CardTitle>WIF Decoding</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="wif-input">WIF Private Key</Label>
            <Input
              id="wif-input"
              value={wifInput || ""}
              onChange={(e) => handleWifInputChange(e.target.value)}
              placeholder="Enter WIF private key"
              className="font-mono"
            />
          </div>

          {wifDecoded && wifDecoded.valid && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Prefix:</span>
                  <div className="font-mono">0x80</div>
                </div>
                <div>
                  <span className="text-muted-foreground">Compressed:</span>
                  <div>{wifDecoded.compressed ? 'true' : 'false'}</div>
                </div>
              </div>
              <div>
                <span className="text-muted-foreground">Private Key (Hex):</span>
                <div className="font-mono bg-muted p-2 rounded text-xs break-all">
                  {wifDecoded.privateKeyHex}
                </div>
              </div>
              <div>
                <span className="text-muted-foreground">Checksum:</span>
                <div className="font-mono bg-muted p-2 rounded text-xs">
                  {wifDecoded.checksum}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* WIF Validation Section */}
      <Card>
        <CardHeader>
          <CardTitle>WIF Validation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="wif-validation">WIF to Validate</Label>
            <Input
              id="wif-validation"
              value={wifValidationInput || ""}
              onChange={(e) => setWifValidationInput(e.target.value)}
              placeholder="Enter WIF to validate"
              className="font-mono"
            />
          </div>

          <div className="flex items-center gap-2">
            <Badge variant={wifValidation.valid ? "default" : "destructive"}>
              {wifValidation.valid ? "Valid" : "Invalid"}
            </Badge>
            {wifValidation.error && (
              <span className="text-sm text-muted-foreground">{wifValidation.error}</span>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}