import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, res) => {
            console.warn('[Vite Proxy Warning] Gagal tersambung ke backend FastAPI (127.0.0.1:8000):', err.message);
            if (res && !res.headersSent && typeof res.writeHead === 'function') {
              res.writeHead(503, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ 
                detail: 'Backend server tidak aktif atau tidak dapat dijangkau di http://127.0.0.1:8000. Pastikan service FastAPI (Uvicorn) sedang berjalan.' 
              }));
            }
          });
        }
      }
    }
  }
});
