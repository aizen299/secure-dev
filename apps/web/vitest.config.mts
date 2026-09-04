import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

/**
 * The dashboard's test runner (ADR 031).
 *
 * `tsconfigPaths` rather than a duplicated alias map: the `@/` prefix is
 * already declared in tsconfig.json, and a second copy of that mapping is a
 * second thing to keep in step. Vite resolves it natively, so no plugin.
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    tsconfigPaths: true,
    alias: {
      // See src/test/server-only-stub.ts for why, and for why this does not
      // weaken the guard it stands in for.
      "server-only": new URL("./src/test/server-only-stub.ts", import.meta.url).pathname,
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // Every mock is undone between tests. A leaked mock makes the next test
    // pass for the wrong reason, which is worse than a failure.
    restoreMocks: true,
  },
});
