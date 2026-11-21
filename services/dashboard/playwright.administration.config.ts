import { defineConfig } from "@playwright/test";
import base from "./playwright.config";
export default defineConfig({
    ...base,
    testMatch: "administration.spec.ts",
    timeout: 180000,
    reporter: [
        ["list"],
        [
            "json",
            {
                outputFile:
                    "../../.runtime/test-reports/phase-21-playwright.json",
            },
        ],
    ],
    outputDir: "../../.runtime/test-reports/phase-21-browser",
});
