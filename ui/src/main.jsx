import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import ErrorBoundary from './components/ErrorBoundary.jsx'
import TauriProvider from './components/TauriProvider.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary>
      <TauriProvider>
        <App />
      </TauriProvider>
    </ErrorBoundary>
  </StrictMode>,
)