import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

// Builds the window into ../assets/ui, which Tauri embeds and which is
// committed, so building Lenstica itself needs no Node. Fixed file names keep
// `src/gui/mod.rs`'s rebuild trigger and the strict CSP (no inline scripts) simple.
export default defineConfig({
  plugins: [svelte(), tailwindcss()],
  base: "./",
  build: {
    outDir: "../assets/ui",
    emptyOutDir: true,
    assetsDir: "",
    cssCodeSplit: false,
    modulePreload: false,
    target: "safari16",
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "[name].js",
        assetFileNames: (asset) => (asset.names?.[0]?.endsWith(".css") ? "app.css" : "[name][extname]"),
      },
    },
  },
});
