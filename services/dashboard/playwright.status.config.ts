import { defineConfig } from "@playwright/test";
import base from "./playwright.config";
export default defineConfig({
    ...base,
    testMatch: "status.spec.ts",
    timeout: 180000,
    reporter: [
        ["list"],
        [
            "json",
            {
                outputFile:
                    "../../.runtime/test-reports/phase-22-playwright.json",
            },
        ],
    ],
    outputDir: "../../.runtime/test-reports/phase-22-browser",
});
