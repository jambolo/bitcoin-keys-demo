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
  encodeWif, 
  decodeWif, 
  validateWif, 
  generateWifSteps,
  isValidHex 
} from '@/lib/bitcoin'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

export function PrivateKeyPage() {
  // Persistent inputs using useKV
  const [privateKeyHex, setPrivateKeyHex] = useKV('private-key-hex', '')
  const [wifInput, setWifInput] = useKV('private-key-wif-input', '')
  const [validationInput, setValidationInput] = useKV('private-key-validation-input', '')
  
  // Shared state for compressed WIF to be used by Public Key page
  const [sharedCompressedWif, setSharedCompressedWif] = useKV('shared-compressed-wif', '')

  // Encoding section
  const [compressedWif, setCompressedWif] = useState('')
  const [uncompressedWif, setUncompressedWif] = useState('')
  const [compressedSteps, setCompressedSteps] = useState<any>(null)
  const [uncompressedSteps, setUncompressedSteps] = useState<any>(null)

  // Decoding section  
  const [decodedData, setDecodedData] = useState<any>(null)

  // Validation section
  const [validation, setValidation] = useState<{ valid: boolean; error?: string }>({ valid: false })

  // Handle private key hex input
  useEffect(() => {
    if (privateKeyHex && isValidHex(privateKeyHex, 64)) {
      const compressed = encodeWif(privateKeyHex, true)
      const uncompressed = encodeWif(privateKeyHex, false)
      const cSteps = generateWifSteps(privateKeyHex, true)
      const uSteps = generateWifSteps(privateKeyHex, false)
      
      setCompressedWif(compressed || '')
      setUncompressedWif(uncompressed || '')
      setCompressedSteps(cSteps)
      setUncompressedSteps(uSteps)
      
      // Update shared compressed WIF for Public Key page
      if (compressed) {
        setSharedCompressedWif(compressed)
        setWifInput(compressed)
        setValidationInput(compressed)
      }
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
  }, [privateKeyHex, setSharedCompressedWif])

  // Handle WIF input
  useEffect(() => {
    if (wifInput) {
      const decoded = decodeWif(wifInput)
      setDecodedData(decoded)
    } else {
      setDecodedData(null)
    }
  }, [wifInput])

  // Handle validation input
  useEffect(() => {
    if (validationInput) {
      const result = validateWif(validationInput)
      setValidation(result)
    } else {
      setValidation({ valid: false })
    }
  }, [validationInput])

  const generateRandom = () => {
    const randomWif = generateRandomPrivateKey()
    const decoded = decodeWif(randomWif)
    if (decoded) {
      setPrivateKeyHex(decoded.privateKeyHex)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold mb-2">Private Key</h2>
        <p className="text-muted-foreground">
          Demonstrates Bitcoin private key encoding, decoding, and validation using WIF format.
        </p>
      </div>

      {/* WIF Encoding Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            WIF Encoding
          </CardTitle>
          <CardDescription>
            Convert a private key from hexadecimal format to Wallet Import Format (WIF)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="private-key-hex">Private Key (Hex)</Label>
              <div className="flex gap-2">
                <Input
                  id="private-key-hex"
                  value={privateKeyHex}
                  onChange={(e) => setPrivateKeyHex(e.target.value)}
                  placeholder="64 character hexadecimal private key"
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
          </div>

          {privateKeyHex && isValidHex(privateKeyHex, 64) && (
            <div className="space-y-6">
              <Separator />
              
              {/* Compressed WIF */}
              <div className="space-y-4">
                <h4 className="font-semibold text-lg">Compressed WIF Process</h4>
                {compressedSteps && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 1: Add Prefix & Compression Flag</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {compressedSteps.step1}
                        </code>
                      </div>
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 2: Double SHA256 Hash</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {compressedSteps.step2}
                        </code>
                      </div>
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 3: Checksum (First 4 bytes)</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {compressedSteps.step3}
                        </code>
                      </div>
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 4: Add Checksum</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {compressedSteps.step4}
                        </code>
                      </div>
                    </div>
                    <div className="flex gap-4 items-start">
                      <div className="flex-1">
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Final: Base58 Encoded WIF (Compressed)</Label>
                        <div className="flex gap-2">
                          <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
                            {compressedWif}
                          </code>
                          <Button
                            variant="outline"
                            size="icon"
                            onClick={() => copyToClipboard(compressedWif)}
                            title="Copy"
                          >
                            <Copy size={16} />
                          </Button>
                        </div>
                      </div>
                      <QRCodeDisplay 
                        value={compressedWif} 
                        title="Compressed WIF" 
                        size={100}
                      />
                    </div>
                  </div>
                )}
              </div>

              <Separator />

              {/* Uncompressed WIF */}
              <div className="space-y-4">
                <h4 className="font-semibold text-lg">Uncompressed WIF Process</h4>
                {uncompressedSteps && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 1: Add Prefix</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {uncompressedSteps.step1}
                        </code>
                      </div>
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 2: Double SHA256 Hash</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {uncompressedSteps.step2}
                        </code>
                      </div>
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 3: Checksum (First 4 bytes)</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {uncompressedSteps.step3}
                        </code>
                      </div>
                      <div>
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Step 4: Add Checksum</Label>
                        <code className="block p-2 bg-muted rounded font-mono text-xs break-all">
                          {uncompressedSteps.step4}
                        </code>
                      </div>
                    </div>
                    <div className="flex gap-4 items-start">
                      <div className="flex-1">
                        <Label className="text-xs uppercase tracking-wide text-muted-foreground">Final: Base58 Encoded WIF (Uncompressed)</Label>
                        <div className="flex gap-2">
                          <code className="flex-1 p-3 bg-accent/10 rounded font-mono text-sm break-all border border-accent/20">
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
                        size={100}
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* WIF Decoding Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            WIF Decoding
          </CardTitle>
          <CardDescription>
            Decode a WIF private key to see its components
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="wif-input">WIF Private Key</Label>
            <Input
              id="wif-input"
              value={wifInput}
              onChange={(e) => setWifInput(e.target.value)}
              placeholder="Enter WIF format private key"
              className="font-mono text-sm"
            />
          </div>

          {decodedData && (
            <div className="space-y-4">
              <Separator />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Prefix</Label>
                  <code className="block p-2 bg-muted rounded font-mono text-sm">0x80</code>
                </div>
                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Private Key (Hex)</Label>
                  <code className="block p-2 bg-muted rounded font-mono text-sm break-all">
                    {decodedData.privateKeyHex}
                  </code>
                </div>
                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Compression Flag</Label>
                  <div className="flex items-center gap-2">
                    <Badge variant={decodedData.compressed ? "default" : "secondary"}>
                      {decodedData.compressed ? 'Compressed' : 'Uncompressed'}
                    </Badge>
                  </div>
                </div>
                <div>
                  <Label className="text-xs uppercase tracking-wide text-muted-foreground">Checksum</Label>
                  <code className="block p-2 bg-muted rounded font-mono text-sm">{decodedData.checksum}</code>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* WIF Validation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            WIF Validation
          </CardTitle>
          <CardDescription>
            Validate any string as a potential WIF private key
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="validation-input">String to Validate</Label>
            <Input
              id="validation-input"
              value={validationInput}
              onChange={(e) => setValidationInput(e.target.value)}
              placeholder="Enter any string to validate as WIF"
              className="font-mono text-sm"
            />
          </div>

          {validationInput && (
            <div className="space-y-2">
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
          )}
        </CardContent>
      </Card>
    </div>
  )
}