import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
export default defineConfig({
    plugins: [react()],
    build: {
        sourcemap: false,
        assetsInlineLimit: 0,
        chunkSizeWarningLimit: 300,
        rolldownOptions:{output:{codeSplitting:{groups:[{name:"react",test:/node_modules\/(react|react-dom|scheduler)\//},{name:"validation",test:/node_modules\/zod\//}]}}},
    },
    test: {
        environment: "jsdom",
        setupFiles: ["./tests/setup.ts"],
        include: ["tests/**/*.test.{ts,tsx}"],
    },
});
