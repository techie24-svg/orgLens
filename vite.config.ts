import { defineConfig, loadEnv, type Plugin, type ViteDevServer } from "vite";
import react from "@vitejs/plugin-react";

// Dev-only: run the /api/* serverless functions inside the Vite dev server so
// `npm run dev` gives the same OAuth + live-scan behavior as Vercel (no Vercel
// CLI/login needed locally). In production these run as real Vercel functions.
const API_ROUTES: Record<string, string> = {
  "/api/oauth/start": "/api/oauth/start.ts",
  "/api/oauth/callback": "/api/oauth/callback.ts",
  "/api/session": "/api/session.ts",
  "/api/scan": "/api/scan.ts",
  "/api/logout": "/api/logout.ts",
};

function devApi(mode: string): Plugin {
  // Surface .env values to the serverless handlers (they read process.env).
  Object.assign(process.env, loadEnv(mode, process.cwd(), ""));
  return {
    name: "orglens-dev-api",
    apply: "serve",
    configureServer(server: ViteDevServer) {
      server.middlewares.use(async (req: any, res: any, next: any) => {
        if (!req.url || !req.url.startsWith("/api/")) return next();
        const url = new URL(req.url, "http://localhost");
        const file = API_ROUTES[url.pathname.replace(/\/+$/, "")];
        if (!file) return next();
        try {
          req.query = Object.fromEntries(url.searchParams);
          const mod = await server.ssrLoadModule(file);
          await mod.default(req, res);
        } catch (e: any) {
          res.statusCode = 500;
          res.end(`Dev API error: ${e?.message ?? e}`);
        }
      });
    },
  };
}

export default defineConfig(({ mode }) => ({
  plugins: [react(), devApi(mode)],
  server: { port: 5174, open: true },
}));
