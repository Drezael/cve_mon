import process from "node:process";
import { URL } from "node:url";
import console from "node:console";
import { chromium, expect } from "@playwright/test";
const browser = await chromium.launch({
    headless: true,
    args: [
        "--host-resolver-rules=MAP dashboard.example.test 127.0.0.1",
        "--no-proxy-server",
    ],
});
try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const failures = [];
    context.on("response", (response) => {
        if (response.status() === 429)
            failures.push(new URL(response.url()).pathname);
    });
    const page = await context.newPage();
    await page.goto(process.env.CVE_E2E_URL + "/login");
    await page.locator("input[name=username]").fill(process.env.CVE_E2E_USER);
    await page
        .locator("input[name=password]")
        .fill(process.env.CVE_E2E_PASSWORD);
    await page.locator("button[type=submit]").click();
    await page.waitForURL("**/dashboard");
    await expect(page.locator(".kpi").first()).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await page.reload();
    await expect(page.locator(".kpi").first()).toBeVisible();
    const tabs = await Promise.all([context.newPage(), context.newPage()]);
    await Promise.all(
        tabs.map(async (tab) => {
            await tab.goto(process.env.CVE_E2E_URL + "/dashboard");
            await expect(tab.locator(".kpi").first()).toBeVisible();
            await expect(tab.getByRole("alert")).toHaveCount(0);
        }),
    );
    // Navigate through the real router before a final overview read.
    await page.getByRole("link", { name: "Server", exact: true }).click();
    const trendResponse = page.waitForResponse((response) =>
        response.url().includes("/overview/trends"),
    );
    await page.getByRole("link", { name: "Übersicht", exact: true }).click();
    const trends = await trendResponse;
    expect(trends.status()).toBe(200);
    await expect(page.getByRole("alert")).toHaveCount(0);
    expect(failures).toEqual([]);
    const abuse = [];
    for (let i = 0; i < 150; i++) {
        const response = await context.request.get(
            process.env.CVE_E2E_URL + "/api/v1/dashboard/overview",
        );
        abuse.push(response.status());
    }
    expect(abuse).toContain(429);
    console.log(
        JSON.stringify({
            fresh_login: true,
            reload: true,
            tabs: 3,
            navigation: true,
            normal_rate_limited: 0,
            abuse_limited: true,
        }),
    );
} finally {
    await browser.close();
}
