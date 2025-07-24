import { defineConfig } from "vite";
import path from "path";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  server: {
    fs: {
      allow: [
        ".",
        path.resolve(__dirname, "../../pkg"),
        // path.resolve(__dirname, "../../../../../rust/cesrox-bindings/cesr/wasm/pkg_web"),
      ],
    },
  },
});
