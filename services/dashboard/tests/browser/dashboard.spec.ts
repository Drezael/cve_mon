import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
const origin = process.env.CVE_E2E_URL!;
async function authorized(context: import("@playwright/test").BrowserContext) {
    await context.addCookies([
        {
            name: "__Host-cve-session",
            value: process.env.CVE_E2E_COOKIE!,
            url: origin,
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
        },
    ]);
}
test("backend outage never becomes zero metrics", async ({ page, context }) => {
    await authorized(context);
    await page.route("**/api/v1/dashboard/overview", (r) =>
        r.fulfill({ status: 503, contentType: "application/json", body: "{}" }),
    );
    await page.goto("/dashboard");
    await expect(page.getByRole("alert")).toContainText("vorübergehend");
    await expect(page.locator(".kpis > .kpi")).toHaveCount(0);
});
test("authenticated tabs can mutate with the same session CSRF token", async ({ page, context }) => {
    await authorized(context);
    await page.goto("/dashboard");
    const other = await context.newPage();
    await other.goto("/dashboard");
    const getToken = async (tab: import("@playwright/test").Page) => tab.evaluate(async () => {
        const r = await fetch("/api/v1/auth/csrf");
        if (!r.ok) throw new Error("CSRF request failed");
        return (await r.json()).csrf_token as string;
    });
    const [a,b] = await Promise.all([getToken(page),getToken(other)]);
    expect(a).toBe(b);
    for (const tab of [page,other]) {
        const status = await tab.evaluate(async (csrf) => {
            const current = await fetch("/api/v1/dashboard/me/locale").then(r=>r.json());
            const changed = await fetch("/api/v1/dashboard/me/locale", {method:"PUT",
                headers:{"Content-Type":"application/json","X-CSRF-Token":csrf,"If-Match":`"${current.version}"`},
                body:JSON.stringify({locale:"de"})});
            return changed.status;
        }, a);
        expect(status).toBe(200);
    }
    await other.close();
});

test("real TLS scoped reads, deep links, CSP, responsive access and logout", async ({
    page,
    context,
}) => {
    await authorized(context);
    page.on("response", (response) => {
        if (
            response.url().includes("/api/v1/dashboard/") &&
            response.status() >= 400
        )
            console.log(
                "Dashboard response",
                response.status(),
                new URL(response.url()).pathname,
            );
    });
    page.on("requestfailed", (request) => {
        if (request.url().includes("/api/v1/dashboard/"))
            console.log(
                "Dashboard request failed",
                new URL(request.url()).pathname,
                request.failure()?.errorText,
            );
    });
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const violations: string[] = [];
    page.on("console", (m) => {
        if (m.text().includes("Content Security Policy"))
            violations.push(m.text());
    });
    const response = await page.goto("/dashboard");
    expect(response?.headers()["content-security-policy"]).toContain(
        "script-src 'self'",
    );
    expect(response?.headers()["cache-control"]).toBe("no-store");
    await expect(
        page.getByRole("heading", { name: "Sicherheitsübersicht" }),
    ).toBeVisible();
    await expect(
        page.getByRole("heading", { name: "Aktive Server" }),
    ).toBeVisible();
    await expect(page.getByText("Daten nicht verfügbar")).toHaveCount(0);
    await page.keyboard.press("Tab");
    await expect(
        page.getByRole("link", { name: "Zum Inhalt springen" }),
    ).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main")).toBeFocused();
    const metrics = await page.evaluate(() => ({
        navigation: performance.getEntriesByType("navigation").map((e) => ({
            duration: e.duration,
            domContentLoaded: (e as PerformanceNavigationTiming)
                .domContentLoadedEventEnd,
        })),
        paint: performance
            .getEntriesByType("paint")
            .map((e) => ({ name: e.name, milliseconds: e.startTime })),
        resources: performance.getEntriesByType("resource").length,
        transferBytes: performance
            .getEntriesByType("resource")
            .reduce(
                (sum, e) => sum + (e as PerformanceResourceTiming).transferSize,
                0,
            ),
    }));
    const { writeFileSync } = await import("node:fs");
    writeFileSync(
        "../../.runtime/test-reports/phase-20-performance.json",
        JSON.stringify(metrics, null, 2),
    );
    expect(metrics.resources).toBeLessThan(35);
    expect(metrics.transferBytes).toBeLessThan(650000);
    await page.screenshot({
        path: "../../.runtime/test-reports/phase-20-dashboard-desktop.png",
        fullPage: true,
    });
    await page.getByRole("link", { name: "Server", exact: true }).click();
    await expect(
        page.getByRole("heading", { name: "Server", exact: true }),
    ).toBeVisible();
    await page
        .getByRole("navigation", { name: "Hauptnavigation" })
        .locator('a[href="/findings"]')
        .click();
    await expect(
        page.getByRole("heading", { name: "Findings", exact: true }),
    ).toBeVisible();
    await page.goBack();
    await expect(
        page.getByRole("heading", { name: "Server", exact: true }),
    ).toBeVisible();
    for (const route of [
        "/dashboard",
        "/servers",
        "/groups",
        `/groups/${process.env.CVE_E2E_GROUP}`,
        "/findings",
        `/findings/${process.env.CVE_E2E_FINDING}`,
        `/servers/${process.env.CVE_E2E_SERVER}`,
        "/notifications",
        `/notifications/${process.env.CVE_E2E_NOTIFICATION}`,
    ]) {
        await page.goto(route);
        await expect(page.locator("h1")).toBeVisible();
        await expect(page.getByText("Daten werden geladen …")).toHaveCount(0, {
            timeout: 12000,
        });
        await expect(page.getByText("Daten nicht verfügbar")).toHaveCount(0);
        const a = await new AxeBuilder({ page })
            .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
            .analyze();
        expect(a.violations, JSON.stringify(a.violations)).toEqual([]);
    }
    for (const width of [320, 768, 1440]) {
        await page.setViewportSize({ width, height: 1000 });
        await page.goto("/dashboard");
        await expect(
            page.getByRole("heading", { name: "Sicherheitsübersicht" }),
        ).toBeVisible();
        await expect(page.locator(".kpis > .kpi")).toHaveCount(4);
        await expect(page.getByText("Daten werden geladen …")).toHaveCount(0);
        expect(
            await page.evaluate(
                () => document.documentElement.scrollWidth <= innerWidth,
            ),
        ).toBe(true);
        await page.screenshot({
            path: `../../.runtime/test-reports/phase-20-dashboard-${width}.png`,
            fullPage: true,
        });
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    const invalid = await page.evaluate(async () => {
        const r = await fetch("/api/does-not-exist");
        return { status: r.status, text: await r.text() };
    });
    expect(invalid.status).toBe(404);
    expect(invalid.text).not.toContain("<!doctype html>");
    const internal = await page.evaluate(
        async () => (await fetch("/internal/jobs")).status,
    );
    expect(internal).toBe(404);
    expect(
        await page.evaluate(
            () =>
                Object.keys(localStorage).length +
                Object.keys(sessionStorage).length,
        ),
    ).toBe(0);
    expect(errors).toEqual([]);
    expect(violations).toEqual([]);
    const tab = await context.newPage();
    await tab.goto("/findings");
    await expect(
        tab.getByRole("heading", { name: "Findings", exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Abmelden" }).click();
    await expect(
        page.getByRole("heading", { name: "Willkommen zurück" }),
    ).toBeVisible();
    await expect(
        tab.getByRole("heading", { name: "Willkommen zurück" }),
    ).toBeVisible();
    await page.goBack();
    await expect(
        page.getByRole("heading", { name: "Willkommen zurück" }),
    ).toBeVisible();
    expect(
        await page.evaluate(
            async () => (await fetch("/api/v1/dashboard/overview")).status,
        ),
    ).toBe(401);
});
test("real password login and viewer navigation", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Benutzername").fill(process.env.CVE_E2E_USER!);
    await page.getByLabel("Passwort", { exact: true }).fill(crypto.randomUUID());
    const rejected = page.waitForResponse(r=>r.url().endsWith("/api/v1/auth/login") && r.status()===401);
    await page.getByRole("button",{name:"Fortfahren"}).click();
    await rejected;
    await expect(page.getByRole("alert")).toBeVisible();
    await page
        .getByLabel("Passwort", { exact: true })
        .fill(process.env.CVE_E2E_PASSWORD!);
    await page.getByRole("button", { name: "Fortfahren" }).click();
    await expect(
        page.getByRole("heading", { name: "Server", exact: true }),
    ).toBeVisible();
    await expect(
        page.getByRole("link", { name: "Übersicht", exact: true }),
    ).toHaveCount(0);
    await page.goto("/dashboard");
    await expect(page.getByRole("alert").first()).toContainText(
        "Zugriff nicht erlaubt",
    );
});

test("real MFA enrollment, recovery handoff and verification", async ({
    page,
}) => {
    test.setTimeout(90000);
    const { createHmac } = await import("node:crypto");
    const otp = (secret: string) => {
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // pragma: allowlist secret -- public RFC 4648 alphabet
        const bits = secret
            .replace(/=+$/, "")
            .split("")
            .map((c) => alphabet.indexOf(c).toString(2).padStart(5, "0"))
            .join("");
        const key = Buffer.from(
            bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)),
        );
        const counter = Buffer.alloc(8);
        counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
        const hash = createHmac("sha1", key).update(counter).digest();
        const offset = hash[19] & 15;
        return ((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000)
            .toString()
            .padStart(6, "0");
    };
    await page.goto("/login");
    await page.getByLabel("Benutzername").fill(process.env.CVE_E2E_MFA_USER!);
    await page
        .getByLabel("Passwort", { exact: true })
        .fill(process.env.CVE_E2E_MFA_PASSWORD!);
    await page.getByRole("button", { name: "Fortfahren" }).click();
    await expect(
        page.getByRole("heading", { name: "Sicherheitsübersicht" }),
    ).toBeVisible();
    await page.goto("/settings/account");
    await page
        .getByRole("button", { name: "MFA einrichten", exact: true })
        .click();
    await page
        .locator("section.admin-form")
        .getByRole("button", { name: "Speichern", exact: true })
        .click();
    await page
        .getByRole("button", { name: "Änderung bestätigen", exact: true })
        .click();
    await page
        .getByLabel("Aktuelles Passwort", { exact: true })
        .fill(process.env.CVE_E2E_MFA_PASSWORD!);
    await page
        .getByRole("button", { name: "Identität bestätigen und speichern" })
        .click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    const secret = await page.locator(".secret").textContent();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    await page.getByLabel("Sechsstelliger Bestätigungscode").fill("000000");
    await page
        .getByRole("button", { name: "MFA aktivieren", exact: true })
        .click();
    await expect(page.getByRole("alert")).toBeVisible();
    await page.getByLabel("Sechsstelliger Bestätigungscode").fill(otp(secret!));
    await page
        .getByRole("button", { name: "MFA aktivieren", exact: true })
        .click();
    await expect(
        page.getByRole("heading", { name: "Wiederherstellungscodes sichern" }),
    ).toBeVisible();
    expect(await page.locator("li code").count()).toBeGreaterThan(0);
    await page
        .getByRole("button", { name: "Sicher aufbewahrt", exact: true })
        .click();
    await page.goto("/dashboard");
    await expect(
        page.getByRole("heading", { name: "Sicherheitsübersicht" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Abmelden" }).click();
    await page.getByLabel("Benutzername").fill(process.env.CVE_E2E_MFA_USER!);
    await page
        .getByLabel("Passwort", { exact: true })
        .fill(process.env.CVE_E2E_MFA_PASSWORD!);
    await page.getByRole("button", { name: "Fortfahren" }).click();
    await expect(
        page.getByRole("heading", { name: "Anmeldung bestätigen" }),
    ).toBeVisible();
    await page.waitForTimeout(
        (31 - (Math.floor(Date.now() / 1000) % 30)) * 1000,
    );
    await page.getByLabel("Sechsstelliger Bestätigungscode").fill(otp(secret!));
    await page.getByRole("button", { name: "Fortfahren" }).click();
    await expect(
        page.getByRole("heading", { name: "Sicherheitsübersicht" }),
    ).toBeVisible();
});
