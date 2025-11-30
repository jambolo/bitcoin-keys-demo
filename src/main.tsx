// Import polyfills first, before any other dependencies
import './lib/polyfills'

import { createRoot } from 'react-dom/client'
import { ErrorBoundary } from "react-error-boundary";
import "@github/spark/spark"

import App from './App.tsx'
import { ErrorFallback } from './ErrorFallback.tsx'

import "./main.css"
import "./index.css"

import { Buffer } from 'buffer';
window.Buffer = Buffer;

// Ensure Buffer is available before starting the app
if (typeof window !== 'undefined') {
  console.log('Buffer availability check:', !!(window as any).Buffer)
  console.log('Process availability check:', !!(window as any).process)
}

createRoot(document.getElementById('root')!).render(
  <ErrorBoundary FallbackComponent={ErrorFallback}>
    <App />
   </ErrorBoundary>
)
