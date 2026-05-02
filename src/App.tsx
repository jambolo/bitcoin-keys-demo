import { useState } from 'react'
import { Box, Container, Tab, Tabs, Typography } from '@mui/material'
import { BitcoinErrorBoundary } from '@/components/BitcoinErrorBoundary'
import { PrivateKeyPage } from '@/components/PrivateKeyPage'
import { PublicKeyPage } from '@/components/PublicKeyPage'
import { AddressPage } from '@/components/AddressPage'
import { MiniKeyPage } from '@/components/MiniKeyPage'
import { SeedPage } from '@/components/SeedPage'
import { Key, Shield, MapPin, Coins, Plant } from '@phosphor-icons/react'

function App() {
  const [activeTab, setActiveTab] = useState('private-key')

  return (
    <Box sx={{ minHeight: '100vh', background: 'linear-gradient(180deg, #f6f8fb 0%, #ffffff 35%, #f7fafc 100%)' }}>
      <Container maxWidth="xl" sx={{ py: 4, px: { xs: 2, md: 3 } }}>
        <Box sx={{ textAlign: 'center', mb: 4 }}>
          <Typography variant="h3" component="h1" sx={{ mb: 1.5, fontWeight: 700 }}>
            Bitcoin Address and Keys Demo
          </Typography>
          <Typography variant="subtitle1" color="text.secondary" sx={{ maxWidth: 760, mx: 'auto' }}>
            Explore Bitcoin cryptography through interactive demonstrations of key generation,
            encoding, and address derivation processes.
          </Typography>
        </Box>

        <Box sx={{ border: 1, borderColor: 'divider', borderRadius: 2, bgcolor: 'background.paper', mb: 3 }}>
          <Tabs
            value={activeTab}
            onChange={(_, value) => setActiveTab(value)}
            variant="scrollable"
            scrollButtons="auto"
            allowScrollButtonsMobile
            sx={{ px: 1.5 }}
          >
            <Tab icon={<Key size={16} />} iconPosition="start" value="private-key" label="Private Key" />
            <Tab icon={<Shield size={16} />} iconPosition="start" value="public-key" label="Public Key" />
            <Tab icon={<MapPin size={16} />} iconPosition="start" value="address" label="Address" />
            <Tab icon={<Coins size={16} />} iconPosition="start" value="mini-key" label="Mini Key" />
            <Tab icon={<Plant size={16} />} iconPosition="start" value="seed" label="Seed Phrase" />
          </Tabs>
        </Box>

          {activeTab === 'private-key' && (
            <BitcoinErrorBoundary fallbackTitle="Private Key Error">
              <PrivateKeyPage />
            </BitcoinErrorBoundary>
          )}

          {activeTab === 'public-key' && (
            <BitcoinErrorBoundary fallbackTitle="Public Key Error">
              <PublicKeyPage />
            </BitcoinErrorBoundary>
          )}

          {activeTab === 'address' && (
            <BitcoinErrorBoundary fallbackTitle="Address Error">
              <AddressPage />
            </BitcoinErrorBoundary>
          )}

          {activeTab === 'mini-key' && (
            <BitcoinErrorBoundary fallbackTitle="Mini Key Error">
              <MiniKeyPage />
            </BitcoinErrorBoundary>
          )}

          {activeTab === 'seed' && (
            <BitcoinErrorBoundary fallbackTitle="Seed Phrase Error">
              <SeedPage />
            </BitcoinErrorBoundary>
          )}
      </Container>
    </Box>
  )
}

export default App