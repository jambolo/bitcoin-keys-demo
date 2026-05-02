// Import polyfills first, before any other dependencies
import './lib/polyfills'

import { createRoot } from 'react-dom/client'
import { ErrorBoundary } from "react-error-boundary";
import { CssBaseline, ThemeProvider, createTheme } from '@mui/material'

import App from './App.tsx'
import { ErrorFallback } from './ErrorFallback.tsx'

import "./main.css"
import "./index.css"

import { Buffer } from 'buffer';
window.Buffer = Buffer;

const appTheme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1f6feb',
    },
    secondary: {
      main: '#ff8f00',
    },
  },
  shape: {
    borderRadius: 10,
  },
})

// Ensure Buffer is available before starting the app
if (typeof window !== 'undefined') {
  console.log('Buffer availability check:', !!(window as any).Buffer)
  console.log('Process availability check:', !!(window as any).process)
}

createRoot(document.getElementById('root')!).render(
  <ThemeProvider theme={appTheme}>
    <CssBaseline />
    <ErrorBoundary FallbackComponent={ErrorFallback}>
      <App />
    </ErrorBoundary>
  </ThemeProvider>
)
