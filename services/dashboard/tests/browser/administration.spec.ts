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
const actors = JSON.parse(process.env.CVE_ADMIN_TEST_ACTORS ?? "[]") as Actor[];
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
test("server registration, dirty navigation, current revision and stale edit", async ({
    page,
    context,
}) => {
    await login(context, 0);
    await page.goto("/servers/manage");
    await page
        .getByRole("button", { name: "Server anlegen", exact: true })
        .click();
    await page
        .getByLabel("Serverbezeichnung", { exact: true })
        .fill("Phase21-Browser-Server");
    await page
        .getByRole("link", { name: "Gruppen", exact: true })
        .last()
        .click();
    await expect(
        page.getByRole("dialog", { name: "Ungespeicherte Änderungen" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Weiter bearbeiten" }).click();
    await accessible(page);
    await save(page, 0);
    await expect(
        page.getByRole("heading", {
            name: "Phase21-Browser-Server",
            exact: true,
        }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Metadaten bearbeiten" }).click();
    await page
        .getByLabel("Serverbezeichnung", { exact: true })
        .fill("Phase21-Server-geändert");
    await save(page, 0);
    await expect(
        page.getByRole("heading", {
            name: "Phase21-Server-geändert",
            exact: true,
        }),
    ).toBeVisible();
    const editUrl = page.url();
    const tab = await context.newPage();
    await tab.goto(editUrl);
    await tab.getByRole("button", { name: "Metadaten bearbeiten" }).click();
    await tab
        .getByLabel("Serverbezeichnung", { exact: true })
        .fill("Veralteter Entwurf");
    await page.getByRole("button", { name: "Metadaten bearbeiten" }).click();
    await page
        .getByLabel("Serverbezeichnung", { exact: true })
        .fill("Neuer bestätigter Stand");
    await save(page, 0);
    await tab.getByRole("button", { name: "Speichern", exact: true }).click();
    await tab
        .getByLabel("Aktuelles Passwort", { exact: true })
        .fill(actors[0].password);
    const target = Math.max(Math.floor(Date.now() / 30000), actors[0].step + 1);
    while (target > Math.floor(Date.now() / 30000) + 1)
        await tab.waitForTimeout(1000);
    await tab
        .getByLabel("MFA-Code, falls eingerichtet", { exact: true })
        .fill(otp(actors[0].secret!, target));
    actors[0].step = target;
    await tab
        .getByRole("button", { name: "Identität bestätigen und speichern" })
        .click();
    await expect(tab.getByRole("alert")).toContainText("Versionskonflikt");
    await expect(
        tab.getByLabel("Serverbezeichnung", { exact: true }),
    ).toHaveValue("Veralteter Entwurf");
    await tab.close();
    await page.screenshot({
        path: "../../.runtime/test-reports/phase-21-server-management.png",
        fullPage: true,
    });
});
test("personal group creation and server keyboard ordering preserve server state", async ({
    page,
    context,
}) => {
    await login(context, 1);
    await page.goto("/groups");
    await page
        .getByRole("button", { name: "Servergruppe anlegen", exact: true })
        .click();
    await page
        .getByLabel("Name", { exact: true })
        .fill("Phase21-Browser-Gruppe");
    await page
        .locator("section.admin-form")
        .getByRole("button", { name: "Speichern", exact: true })
        .click();
    await expect(
        page.getByRole("link", { name: "Phase21-Browser-Gruppe", exact: true }),
    ).toBeVisible();
    await page.goto("/servers/order");
    await expect(
        page.getByRole("heading", { name: "Manuelle Reihenfolge" }),
    ).toBeVisible();
    const down = page.getByRole("button", {
        name: "1: Nach unten",
        exact: true,
    });
    await down.focus();
    await page.keyboard.press("Enter");
    await expect(
        page.getByRole("button", {
            name: "Ungespeicherte Reihenfolge verwerfen",
            exact: true,
        }),
    ).toBeVisible();
    await page
        .getByRole("button", { name: "Reihenfolge prüfen und speichern" })
        .click();
    await save(page, 1);
    await expect(page.getByRole("status").first()).toContainText(
        "Reihenfolge bestätigt",
    );
    await accessible(page);
});
test("triage, plain-text notes and finite exceptions", async ({
    page,
    context,
}) => {
    await login(context, 2);
    await page.goto("/findings/" + process.env.CVE_E2E_FINDING + "/edit");
    await page.getByRole("button", { name: "Triage", exact: true }).click();
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Browserprüfung der tatsächlichen Evidenz");
    await page.getByRole("button", { name: "Speichern", exact: true }).click();
    await expect(page.getByRole("status").first()).toContainText("bestätigt");
    await page
        .getByRole("button", { name: "Notiz hinzufügen", exact: true })
        .click();
    await page
        .getByLabel("Bearbeitungsnotiz")
        .fill("<img src=x onerror=alert(1)>");
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Notiz ist nur Text");
    await page.getByRole("button", { name: "Speichern", exact: true }).click();
    await expect(page.getByRole("status").first()).toContainText("bestätigt");
    expect(await page.locator("img").count()).toBe(0);
    await page
        .getByRole("button", { name: "Risikoausnahme beantragen" })
        .click();
    await page.getByLabel("Gültig ab").fill("2026-11-09T00:00");
    await page.getByLabel("Gültig bis").fill("2026-11-08T00:00");
    await page
        .getByLabel("Risikokontext und Verantwortung")
        .fill("Temporäre Prüfung durch Security Operations");
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Endliche dokumentierte Ausnahme");
    await page.getByRole("button", { name: "Speichern", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("endlicher Zeitraum");
    await page.getByRole("button", { name: "Abbrechen", exact: true }).click();
    await page.getByRole("button", { name: "Änderungen verwerfen" }).click();
    await accessible(page);
});
test("notification preference, disabled rule and safe template preview", async ({
    page,
    context,
}) => {
    await login(context, 3);
    await page.goto("/settings/preferences");
    await page.getByRole("button", { name: "Präferenzen bearbeiten" }).click();
    await page.getByLabel("Versandform").selectOption("digest");
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Tägliche Zusammenfassung");
    await page.getByRole("button", { name: "Speichern", exact: true }).click();
    await expect(page.getByRole("status").first()).toContainText("gespeichert");
    await page.goto("/administration/rules");
    await page
        .getByRole("button", { name: "Regel erstellen", exact: true })
        .click();
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Deaktivierte Browser-Testregel");
    await save(page, 3, true);
    await expect(page.getByRole("status").first()).toContainText(
        "Regelversion bestätigt",
    );
    await page.goto("/administration/templates");
    await page
        .getByRole("button", { name: "Vorlage zur Vorschau auswählen" })
        .first()
        .click();
    await page
        .getByLabel("HTML-Version", { exact: true })
        .fill("<p>${items}</p>");
    await page
        .getByRole("button", { name: "Sichere Vorschau erzeugen" })
        .click();
    await expect(
        page.getByRole("region", { name: "Kontrollierte Vorschau" }),
    ).toContainText("Beispielserver");
    expect(
        await page
            .locator(
                ".template-preview img, .template-preview iframe, .template-preview script",
            )
            .count(),
    ).toBe(0);
    await accessible(page);
});
test("user administration does not grant administrator implicitly", async ({
    page,
    context,
}) => {
    await login(context, 4);
    await page.goto("/administration/users");
    await page
        .getByRole("button", { name: "Benutzer erstellen", exact: true })
        .click();
    await page
        .getByLabel("Benutzername", { exact: true })
        .fill("browser-user-phase21");
    await page
        .getByLabel("Anzeigename", { exact: true })
        .fill("Browser Benutzer");
    await page
        .getByLabel("E-Mail-Adresse", { exact: true })
        .fill("browser-user@example.test");
    await save(page, 4);
    await expect(
        page.getByRole("heading", { name: "Browser Benutzer", exact: true }),
    ).toBeVisible();
    await expect(
        page.getByText("Aktivierung ausstehend", { exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Rollenzuweisung ändern" }).click();
    await page.getByLabel("Viewer", { exact: true }).check();
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Explizite Leserechte");
    await save(page, 4, true);
    await expect(page.getByRole("status").first()).toContainText(
        "Benutzeränderung bestätigt",
    );
    await accessible(page);
});
test("existing server upload gives 202 receipt and bounded separate processing status", async ({
    page,
    context,
}) => {
    await login(context, 5);
    await page.goto("/servers/upload");
    await page
        .getByLabel(process.env.CVE_E2E_SERVER_NAME!, { exact: true })
        .check();
    await page.getByLabel("JSON-Datei", { exact: true }).setInputFiles({
        name: "browser-phase21.json",
        mimeType: "application/json",
        buffer: Buffer.from(process.env.CVE_E2E_INVENTORY!),
    });
    await page
        .getByRole("button", { name: "Server speichern", exact: true })
        .click();
    await expect(
        page.getByRole("heading", { name: "Annahme bestätigt" }),
    ).toBeVisible();
    await expect(page.getByText("HTTP 202:", { exact: false })).toBeVisible();
    await expect(
        page.getByRole("heading", { name: "Verarbeitungsstatus", exact: true }),
    ).toBeVisible();
    await accessible(page);
    for (const width of [320, 768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        await page.goto("/servers/manage");
        await expect(
            page.getByRole("heading", {
                name: "Serververwaltung",
                exact: true,
            }),
        ).toBeVisible();
        expect(
            await page.evaluate(
                () => document.documentElement.scrollWidth <= window.innerWidth,
            ),
        ).toBe(true);
        await page.screenshot({
            path: `../../.runtime/test-reports/phase-21-admin-${width}.png`,
            fullPage: true,
        });
        await accessible(page);
    }
});
test("viewer cannot enter user management or see administrative write actions", async ({
    page,
    context,
}) => {
    await login(context, 6);
    await page.goto("/administration/users");
    await expect(page.getByRole("alert")).toContainText("Berechtigung");
    await expect(
        page.getByRole("button", { name: "Benutzer erstellen" }),
    ).toHaveCount(0);
    await page.goto("/servers/manage");
    await expect(
        page.getByRole("button", { name: "Server anlegen" }),
    ).toHaveCount(0);
    await accessible(page);
});

test("explicit server ACL grant and revoke change the next protected read", async ({
    page,
    context,
    browser,
}) => {
    await login(context, 7);
    const server = process.env.CVE_E2E_SERVER_ID!;
    await page.goto("/servers/access/" + server);
    await page.getByLabel(actors[6].name, { exact: true }).check();
    await page
        .getByRole("button", { name: "Benutzer zur Bearbeitung hinzufügen" })
        .click();
    const entry = page.getByRole("group", {
        name: actors[6].name,
        exact: true,
    });
    await entry.getByLabel("Server lesen", { exact: true }).check();
    await entry.getByLabel("Findings lesen", { exact: true }).check();
    await page.getByRole("button", { name: "ACL-Änderung prüfen" }).click();
    await expect(
        entry.getByLabel("Server lesen", { exact: true }),
    ).toBeDisabled();
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Explizite serverbezogene Leserechte");
    await save(page, 7, true);
    await expect(
        page
            .getByRole("group", { name: actors[6].name, exact: true })
            .getByLabel("Server lesen", { exact: true }),
    ).toBeChecked();
    const reader = await browser.newContext({ ignoreHTTPSErrors: true });
    const tab = await reader.newPage();
    await tab.goto("/login");
    await tab.getByLabel("Benutzername", { exact: true }).fill(actors[6].name);
    await tab.getByLabel("Passwort", { exact: true }).fill(actors[6].password);
    await tab.getByRole("button", { name: "Fortfahren", exact: true }).click();
    await expect(
        tab.getByRole("heading", { name: "Server", exact: true }),
    ).toBeVisible();
    await tab.goto("/servers/" + server);
    await expect(
        tab.getByRole("heading", {
            name: process.env.CVE_E2E_SERVER_NAME!,
            exact: true,
        }),
    ).toBeVisible();
    await page
        .getByRole("group", { name: actors[6].name, exact: true })
        .getByRole("button", { name: "ACL-Eintrag entfernen" })
        .click();
    await page.getByRole("button", { name: "ACL-Änderung prüfen" }).click();
    await page
        .getByLabel("Begründung", { exact: true })
        .fill("Expliziter Rechteentzug");
    await save(page, 7, true);
    await tab.reload();
    // ACL changes increment auth_version: existing sessions are invalidated.
    await expect(
        tab.getByRole("heading", { name: "Willkommen zurück" }),
    ).toBeVisible();
    await tab.getByLabel("Benutzername", { exact: true }).fill(actors[6].name);
    await tab.getByLabel("Passwort", { exact: true }).fill(actors[6].password);
    await tab.getByRole("button", { name: "Fortfahren", exact: true }).click();
    await expect(
        tab.getByRole("button", { name: "Abmelden", exact: true }),
    ).toBeVisible();
    await tab.goto("/servers/" + server);
    await expect(tab.getByRole("alert")).toContainText("nicht verfügbar");
    await reader.close();
    await accessible(page);
});

test("bounded administration lists and responsive page performance", async ({
    page,
    context,
}) => {
    await login(context, 8);
    const measurements = [];
    for (const width of [320, 768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        const start = Date.now();
        const pending = page.waitForResponse(
            (r) =>
                new URL(r.url()).pathname ===
                    "/api/v1/dashboard/admin/servers" && r.status() === 200,
            { timeout: 8000 },
        );
        await page.goto("/servers/manage");
        const response = await pending;
        const body = (await response.json()) as {
            items: unknown[];
            limit: number;
        };
        await expect(
            page.getByRole("heading", { name: "Bestand", exact: true }),
        ).toBeVisible();
        const elapsedMs = Date.now() - start;
        expect(elapsedMs).toBeLessThan(8000);
        expect(body.limit).toBe(25);
        expect(body.items.length).toBeLessThanOrEqual(25);
        expect(
            await page.evaluate(
                () => document.documentElement.scrollWidth <= window.innerWidth,
            ),
        ).toBe(true);
        measurements.push({
            width,
            elapsedMs,
            rows: body.items.length,
            bytes: (await response.body()).length,
        });
        await accessible(page);
        await page.screenshot({
            path: `../../.runtime/test-reports/phase-21-performance-${width}.png`,
            fullPage: true,
        });
    }
    writeFileSync(
        "../../.runtime/test-reports/phase-21-browser-performance.json",
        JSON.stringify(measurements, null, 2),
    );
});
