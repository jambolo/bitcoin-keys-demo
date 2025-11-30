import { useState, useEffect } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { BitcoinErrorBoundary } from '@/components/BitcoinErrorBoundary'
import { PrivateKeyPage } from '@/components/PrivateKeyPage'
import { PublicKeyPage } from '@/components/PublicKeyPage'
import { AddressPage } from '@/components/AddressPage'
import { MiniKeyPage } from '@/components/MiniKeyPage'
import { SeedPage } from '@/components/SeedPage'
import { Key, Shield, MapPin, Coins, Plant } from '@phosphor-icons/react'

function App() {
  const [activeTab, setActiveTab] = useState('private-key')

  // No initialization needed for bitcoin-lite
  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto py-8 px-4">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-foreground mb-4">Bitcoin Address and Keys Demo</h1>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Explore Bitcoin cryptography through interactive demonstrations of key generation, 
            encoding, and address derivation processes.
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5 mb-8">
            <TabsTrigger value="private-key" className="flex items-center gap-2">
              <Key size={16} />
              Private Key
            </TabsTrigger>
            <TabsTrigger value="public-key" className="flex items-center gap-2">
              <Shield size={16} />
              Public Key
            </TabsTrigger>
            <TabsTrigger value="address" className="flex items-center gap-2">
              <MapPin size={16} />
              Address
            </TabsTrigger>
            <TabsTrigger value="mini-key" className="flex items-center gap-2">
              <Coins size={16} />
              Mini Key
            </TabsTrigger>
            <TabsTrigger value="seed" className="flex items-center gap-2">
              <Plant size={16} />
              Seed Phrase
            </TabsTrigger>
          </TabsList>

          <TabsContent value="private-key">
            <BitcoinErrorBoundary fallbackTitle="Private Key Error">
              <PrivateKeyPage />
            </BitcoinErrorBoundary>
          </TabsContent>

          <TabsContent value="public-key">
            <BitcoinErrorBoundary fallbackTitle="Public Key Error">
              <PublicKeyPage />
            </BitcoinErrorBoundary>
          </TabsContent>

          <TabsContent value="address">
            <BitcoinErrorBoundary fallbackTitle="Address Error">
              <AddressPage />
            </BitcoinErrorBoundary>
          </TabsContent>

          <TabsContent value="mini-key">
            <BitcoinErrorBoundary fallbackTitle="Mini Key Error">
              <MiniKeyPage />
            </BitcoinErrorBoundary>
          </TabsContent>

          <TabsContent value="seed">
            <BitcoinErrorBoundary fallbackTitle="Seed Phrase Error">
              <SeedPage />
            </BitcoinErrorBoundary>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}

export default App