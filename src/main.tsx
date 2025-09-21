// Import polyfills first, before any other dependencies
import './lib/polyfills'

import { createRoot } from 'react-dom/client'
import { ErrorBoundary } from "react-error-boundary";
import "@github/spark/spark"

import App from './App.tsx'
import { ErrorFallback } from './ErrorFallback.tsx'

import "./main.css"
import "./styles/theme.css"
import "./index.css"

// Ensure Buffer is available before starting the app
if (typeof window !== 'undefined') {
  console.log('Buffer availability check:', !!window.Buffer)
}

createRoot(document.getElementById('root')!).render(
  <ErrorBoundary FallbackComponent={ErrorFallback}>
    <App />
   </ErrorBoundary>
)
