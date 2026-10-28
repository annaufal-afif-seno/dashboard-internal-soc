import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const port = parseInt(env.VITE_PORT || process.env.PORT || '5173', 10);
  const target = env.VITE_API_URL || process.env.VITE_API_URL || 'http://127.0.0.1:8003';

  return {
    plugins: [react()],
    server: {
      port,
      host: true,
      proxy: {
        '/api': {
          target,
          changeOrigin: true,
        },
      },
    },
  };
});
