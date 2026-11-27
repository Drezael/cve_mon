import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
type Actor = {
    cookie: string;
    password: string;
    secret?: string;
    step: number;
    name: string;
};
const actors = JSON.parse(
    process.env.CVE_STATUS_TEST_ACTORS ?? "[]",
) as Actor[];
async function login(context: BrowserContext, index: number) {
    await context.addCookies([
        {
            name: "__Host-cve-session",
            value: actors[index].cookie,
            url: process.env.CVE_E2E_URL!,
            secure: true,
            httpOnly: true,
            sameSite: "Strict",
        },
    ]);
}
function otp(secret: string, step: number) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // pragma: allowlist secret -- RFC alphabet
    const bits = secret
        .replace(/=+$/, "")
        .split("")
        .map((c) => alphabet.indexOf(c).toString(2).padStart(5, "0"))
        .join("");
    const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step));
    const hash = createHmac("sha1", key).update(counter).digest();
    const offset = hash[19] & 15;
    return ((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000)
        .toString()
        .padStart(6, "0");
}
async function save(page: Page, index: number, critical = false) {
    await page.getByRole("button", { name: "Speichern", exact: true }).click();
    if (critical)
        await page
            .getByRole("button", { name: "Änderung bestätigen", exact: true })
            .click();
    const actor = actors[index];
    await expect(
        page.getByRole("dialog", { name: "Identität erneut bestätigen" }),
    ).toBeVisible();
    await page
        .getByLabel("Aktuelles Passwort", { exact: true })
        .fill(actor.password);
    if (actor.secret) {
        const target = Math.max(Math.floor(Date.now() / 30000), actor.step + 1);
        while (target > Math.floor(Date.now() / 30000) + 1)
            await page.waitForTimeout(1000);
        await page
            .getByLabel("MFA-Code, falls eingerichtet", { exact: true })
            .fill(otp(actor.secret, target));
        actor.step = target;
    }
    await page
        .getByRole("button", { name: "Identität bestätigen und speichern" })
        .click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.getByRole("alert")).toHaveCount(0);
}
async function accessible(page: Page) {
    const result = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
        .analyze();
    expect(result.violations, JSON.stringify(result.violations)).toEqual([]);
}

test("real TLS status overview, service, pipeline and accessible history", async ({
    page,
    context,
}) => {
    await login(context, 0);
    await page.goto("/status");
    await expect(
        page.getByRole("heading", {
            name: "Aktueller Plattformzustand",
            exact: true,
        }),
    ).toBeVisible();
    await expect(
        page.getByText("Messabdeckung:", { exact: false }),
    ).toBeVisible();
    await accessible(page);
    await page.getByRole("link", { name: "FastAPI", exact: true }).click();
    await expect(
        page.getByRole("heading", { name: "Prüfdimensionen", exact: true }),
    ).toBeVisible();
    await expect(
        page.getByRole("table", { name: /Diagrammalternative/ }),
    ).toBeVisible();
    await page
        .getByRole("combobox", { name: "Messreihe", exact: true })
        .selectOption("readiness");
    await page.setViewportSize({ width: 390, height: 900 });
    const region = page.getByRole("region", { name: "Scrollbare Tabelle" });
    await page
        .getByRole("combobox", { name: "Messreihe", exact: true })
        .focus();
    for (let i = 0; i < 10; i++) {
        await page.keyboard.press("Tab");
        if (
            await region.evaluate(
                (element) => element === document.activeElement,
            )
        )
            break;
    }
    await expect(region).toBeFocused();
    await page.keyboard.press("ArrowRight");
    await expect
        .poll(() => region.evaluate((element) => element.scrollLeft))
        .toBeGreaterThan(0);
    await accessible(page);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page
        .getByRole("combobox", { name: "Messreihe", exact: true })
        .selectOption("backlog");
    await expect(
        page.getByText("Keine Rohmessungen verfügbar.", { exact: true }),
    ).toBeVisible();
    await page.goto("/status/pipelines/inventory");
    await expect(
        page.getByRole("heading", {
            name: "Inventarverarbeitung",
            exact: true,
        }),
    ).toBeVisible();
    await page.goto("/status/incidents");
    await expect(
        page.getByRole("heading", { name: "Störungsverlauf", exact: true }),
    ).toBeVisible();
    await accessible(page);
});
test("real maintenance metadata uses MFA and preserves raw states", async ({
    page,
    context,
}) => {
    await login(context, 1);
    await page.goto("/status/maintenance");
    await page
        .getByRole("button", { name: "Wartungsfenster planen", exact: true })
        .click();
    await page.getByLabel("FastAPI", { exact: true }).check();
    await page
        .getByLabel("Wartungsbeginn", { exact: true })
        .fill("2026-11-10T01:00");
    await page
        .getByLabel("Wartungsende", { exact: true })
        .fill("2026-11-11T01:00");
    await page
        .getByLabel("Öffentliche Beschreibung für Statusberechtigte", {
            exact: true,
        })
        .fill("Phase22 Browserwartung <script>");
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Explizit genehmigte Testwartung");
    await accessible(page);
    await save(page, 1, true);
    await expect(page.getByRole("status").first()).toContainText("bestätigt");
    expect(await page.locator("script:not([src])").count()).toBe(0);
    await expect(
        page.getByRole("heading", {
            name: "Phase22 Browserwartung <script>",
            exact: true,
        }),
    ).toBeVisible();
    const maintenance = page.locator("article").filter({
        has: page.getByRole("heading", {
            name: "Phase22 Browserwartung <script>",
            exact: true,
        }),
    });
    await maintenance
        .getByRole("button", { name: "Wartung absagen", exact: true })
        .click();
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Testwartung nachvollziehbar abgesagt");
    await save(page, 1, true);
    await expect(
        maintenance.getByRole("button", {
            name: "Wartung absagen",
            exact: true,
        }),
    ).toBeDisabled();
    await accessible(page);
});
test("analyst and viewer cannot access administrative status", async ({
    page,
    context,
    browser,
}) => {
    await login(context, 2);
    await page.goto("/status");
    await expect(page.getByRole("alert")).toContainText(
        "Statuszugriff nicht erlaubt",
    );
    await expect(
        page.getByRole("link", { name: "FastAPI", exact: true }),
    ).toHaveCount(0);
    await page.goto("/status/services/api");
    await expect(page.getByRole("alert")).toContainText(
        "Statuszugriff nicht erlaubt",
    );
    const viewer = await browser.newContext({ ignoreHTTPSErrors: true });
    await login(viewer, 3);
    const tab = await viewer.newPage();
    await tab.goto("/status");
    await expect(tab.getByRole("alert")).toContainText(
        "Statuszugriff nicht erlaubt",
    );
    await viewer.close();
    await accessible(page);
});
test("backend failure removes healthy display, mobile layouts and bounded polling", async ({
    page,
    context,
}) => {
    await login(context, 4);
    const measurements = [];
    for (const width of [320, 768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        const start = Date.now();
        await page.goto("/status");
        await expect(
            page.getByRole("heading", {
                name: "Aktueller Plattformzustand",
                exact: true,
            }),
        ).toBeVisible();
        const elapsedMs = Date.now() - start;
        expect(elapsedMs).toBeLessThan(8000);
        expect(
            await page.evaluate(
                () => document.documentElement.scrollWidth <= window.innerWidth,
            ),
        ).toBe(true);
        measurements.push({ width, elapsedMs });
        await accessible(page);
        await page.screenshot({
            path: `../../.runtime/test-reports/phase-22-status-${width}.png`,
            fullPage: true,
        });
    }
    writeFileSync(
        "../../.runtime/test-reports/phase-22-browser-performance.json",
        JSON.stringify(measurements, null, 2),
    );
    await page.route("**/api/v1/status/overview", (route) =>
        route.fulfill({
            status: 503,
            contentType: "application/problem+json",
            body: JSON.stringify({ title: "Service unavailable" }),
        }),
    );
    await page
        .getByRole("button", { name: "Status aktualisieren", exact: true })
        .click();
    await expect(page.getByRole("alert")).toContainText(
        "Plattformzustand ist unbekannt",
    );
    await expect(
        page.getByRole("heading", {
            name: "Aktueller Plattformzustand",
            exact: true,
        }),
    ).toHaveCount(0);
    await accessible(page);
});
