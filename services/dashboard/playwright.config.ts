import { defineConfig } from "@playwright/test";
export default defineConfig({
    testDir: "tests/browser",
    testMatch: "dashboard.spec.ts",
    workers: 1,
    retries: 0,
    timeout: 45000,
    reporter: [
        ["list"],
        [
            "json",
            {
                outputFile:
                    "../../.runtime/test-reports/phase-20-playwright.json",
            },
        ],
    ],
    use: {
        baseURL: process.env.CVE_E2E_URL,
        ignoreHTTPSErrors: true,
        launchOptions: {
            args: [
                "--host-resolver-rules=MAP dashboard.example.test 127.0.0.1",
                "--no-proxy-server",
            ],
        },
        viewport: { width: 1440, height: 1000 },
        reducedMotion: "reduce",
    },
    outputDir: "../../.runtime/test-reports/phase-20-browser",
});
