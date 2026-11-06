import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

// Ensure any previously installed offline Service Workers or stale Workbox caches
// on Android Chrome are cleared so the app always tracks & updates live from the server
// over Wi-Fi or mobile data.
if (typeof window !== 'undefined') {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker
      .getRegistrations()
      .then((registrations) => {
        for (const registration of registrations) {
          void registration.unregister();
        }
      })
      .catch(() => {});
  }
  if ('caches' in window) {
    caches
      .keys()
      .then((keys) => {
        for (const key of keys) {
          void caches.delete(key);
        }
      })
      .catch(() => {});
  }
}

createRoot(document.getElementById('root')!).render(<App />);
