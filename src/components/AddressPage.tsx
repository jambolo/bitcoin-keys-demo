import * as bitcoin from 'bitcoinjs-lib'

import { Card, CardContent, CardDescription
import { Label } from '@/components/ui/labe
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
  validateBitcoinAddress,
  BitcoinKeyData,
} from '@/lib/bitcoin'

  // Pers
  const [hexInput, setHexInp
  const [hashInput, 
  const [validationI
  validateBitcoinAddress,
  decodeAddress,
  BitcoinKeyData,
  isValidHex
} from '@/lib/bitcoin'
import { QRCodeDisplay } from '@/components/QRCodeDisplay'

export function AddressPage() {
  // Persistent inputs using useKV
  const [wifInput, setWifInput] = useKV('address-wif-input', '')
  const [hexInput, setHexInput] = useKV('address-hex-input', '')
  const [pubkeyInput, setPubkeyInput] = useKV('address-pubkey-input', '')
  const [hashInput, setHashInput] = useKV('address-hash-input', '')
  const [addressInput, setAddressInput] = useKV('address-decode-input', '')
  const [validationInput, setValidationInput] = useKV('address-validation-input', '')

        
          publicKeyHex: pubkeyInput,
          p2pkhAddress: p2pkh.address || 'N/A',

        }
        // Invalid 
      }

        const hashB
        const p2pkh = bitcoin.payments.p
        const p2sh = bitcoin.payments.p2sh({ redeem: p
        data = {
          p2pkhAddress: p2pkh.address || 'N/A',
          bech32Address: p2wpkh.address || 'N/A'
        }
        // Invalid hash
      }

  }, [wi
  // Auto-populate validation input with generated taproot address
    if (derivedData?.taprootAddress && derivedData.taprootAddress !== 'N
    }

  useEffect(() => {
      const d
    } else {
    }

  useEffect
      const resul
    } else {
    }

    const random
    setHexInput('')
    setHashInput('')

    if (navigator.clipboard) {
    }

    setWi
    setPubkeyIn
  }
  return (
      <
        <p className="text-muted-foreground">
        </p>

      <Card>
        
            Address Derivation
          <CardDescription>
          </CardDescription>
        
            <Tab
              <TabsTrigger value="h
              <TabsTrigger value="hash">Hash</T

              <div className="space-y-2">
                <div className="flex gap-2">
         
               
                    cla
                  <
       
     

            <TabsContent
                <Label htmlFor="hex-derivation">Pr

                  onChange={(e) => setHexInput(e.target.value)}
                  c
              </div>

     
                <Input

                  placeholde
                />
            </TabsConte
            <TabsContent value="hash" className="
                <Label htmlFor="
            
                  onChange={(
     
              </div>

          {derivedData
              <Sepa
              {/* Key Chai
                <h4 className="font-semibold text-lg">Derive
                  {derivedD
            
                        <code classNa
     
                       

  const generateRandom = () => {
    const randomWif = generateRandomPrivateKey()
    setWifInput(randomWif)
    setHexInput('')
    setPubkeyInput('')
    setHashInput('')
  }

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(console.error)
    }
  }

  const clearInputs = () => {
    setWifInput('')
    setHexInput('')
    setPubkeyInput('')
    setHashInput('')
  }

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold mb-2">Address</h2>
        <p className="text-muted-foreground">
          Generate Bitcoin addresses from keys and decode existing addresses.
        </p>
      </div>

      {/* Derivation Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />
            Address Derivation
          </CardTitle>
          <CardDescription>
            Generate Bitcoin addresses from private keys, public keys, or hashes
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <Tabs defaultValue="wif" className="w-full">
            <TabsList className="grid grid-cols-4 w-full">
              <TabsTrigger value="wif">WIF</TabsTrigger>
              <TabsTrigger value="hex">Private Key</TabsTrigger>
              <TabsTrigger value="pubkey">Public Key</TabsTrigger>
              <TabsTrigger value="hash">Hash</TabsTrigger>
            </TabsList>

            <TabsContent value="wif" className="space-y-4">
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
                  <Button variant="outline" size="icon" onClick={generateRandom} title="Generate Random">
                    <Shuffle size={16} />
                  </Button>
                  <Button variant="outline" onClick={clearInputs}>Clear</Button>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="hex" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="hex-derivation">Private Key (Hex)</Label>
                <Input
                  id="hex-derivation"
                  value={hexInput}
                  onChange={(e) => setHexInput(e.target.value)}
                  placeholder="64 character hexadecimal private key"
                  className="font-mono text-sm"
                />
              </div>
            </TabsContent>

            <TabsContent value="pubkey" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="pubkey-derivation">Public Key (Hex)</Label>
                <Input
                  id="pubkey-derivation"
                  value={pubkeyInput}
                  onChange={(e) => setPubkeyInput(e.target.value)}
                  placeholder="66 or 130 character hexadecimal public key"
                  className="font-mono text-sm"
                />
              </div>
            </TabsContent>

            <TabsContent value="hash" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="hash-derivation">Public Key Hash (Hex)</Label>
                <Input
                  id="hash-derivation"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="40 character hexadecimal hash"
                  className="font-mono text-sm"
                />
              </div>
            </TabsContent>
          </Tabs>

          {derivedData && (
            <div className="space-y-6">
              <Separator />
              
                        </div>
                      {decodedAddress.wit
                          <span className="text-muted-foreground">Script Type:</sp
                        </div>
                    </div>
                )}
            </div>
        </CardContent>

      <Card>
          <CardTitle className=
            Address Validation
          <CardDescription>
          </CardDescription>
        <CardContent classNa
            <Label htmlFor
              id="ad

              className="font-mono text-sm"
          </div>
          {validationInput && (
              <Label className="text-xs uppercase 
                <Badge variant={validation.valid ? "default" : "destructive"}>
                </Badge>
                  <span classNa
              </div>
          )}
      </Card>
  )






















































































































































































































                      )}
                      {decodedAddress.witnessVersion === 1 && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Script Type:</span>
                          <span>Pay-to-Taproot</span>

                      )}

                  </div>

              </div>

          )}

      </Card>

      {/* Validation Section */}

        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRight className="text-accent" />

          </CardTitle>

            Validate any string as a potential Bitcoin address

        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="address-validation">String to Validate</Label>
            <Input
              id="address-validation"
              value={validationInput}
              onChange={(e) => setValidationInput(e.target.value)}
              placeholder="Enter any string to validate as Bitcoin address"

            />



            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wide text-muted-foreground">Validation Result</Label>
              <div className="flex items-center gap-2">

                  {validation.valid ? 'Valid' : 'Invalid'}

                {validation.error && (
                  <span className="text-sm text-destructive">{validation.error}</span>
                )}

            </div>

        </CardContent>

    </div>

}