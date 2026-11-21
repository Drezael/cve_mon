import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Administration, { LegacyAdministrationRedirect } from "../src/admin";
import * as auth from "../src/auth";
import * as ui from "../src/ui";

afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
function setup(permissions: string[], path = "/settings", roles = ["user"]) {
    vi.spyOn(auth, "useAuth").mockReturnValue({
        identity: {
            state: "authenticated",
            permissions,
            roles,
            privateKey: crypto.randomUUID(),
        },
        checking: false,
        enrollmentSecret: null,
        setEnrollmentSecret: vi.fn(),
        recoveryCodes: [],
        setRecoveryCodes: vi.fn(),
        refresh: vi.fn(),
        logoutError: "",
        logout: vi.fn(),
    });
    render(
        <MemoryRouter initialEntries={[path]}>
            <Routes>
                <Route path="/settings/*" element={<Administration />} />
                <Route
                    path="/administration/*"
                    element={<LegacyAdministrationRedirect />}
                />
            </Routes>
        </MemoryRouter>,
    );
}
it("combines personal and permitted instance settings under settings", () => {
    setup(["notification:read", "notification:smtp:manage", "user:list"]);
    expect(
        screen.getByRole("link", { name: "Meine Mail-Einstellungen" }),
    ).toHaveAttribute("href", "/settings/mail");
    expect(
        screen.getByRole("link", { name: "Zentrale SMTP-Einstellungen" }),
    ).toHaveAttribute("href", "/settings/smtp");
    expect(screen.getByRole("link", { name: "Benutzer" })).toHaveAttribute(
        "href",
        "/settings/users",
    );
    expect(screen.getByRole("link", { name: "Kontosicherheit" })).toBeVisible();
});
it("hides settings without their required permissions even for an admin role", () => {
    setup(["notification:read"], "/settings", ["admin", "user"]);
    expect(
        screen.queryByRole("link", { name: "Benutzer" }),
    ).not.toBeInTheDocument();
    expect(
        screen.queryByRole("link", { name: "Zentrale SMTP-Einstellungen" }),
    ).not.toBeInTheDocument();
    expect(
        screen.getByRole("link", { name: "Meine Mail-Einstellungen" }),
    ).toBeVisible();
});
it.each([
    "/settings/smtp",
    "/settings/users",
    "/settings/instance",
    "/administration/smtp",
])("blocks unauthorized direct links before requesting data: %s", (path) => {
    const data = vi.spyOn(ui, "useData");
    setup([], path);
    expect(
        screen.getByRole("heading", { name: "Zugriff nicht erlaubt" }),
    ).toBeVisible();
    expect(data).not.toHaveBeenCalled();
});
it("blocks user detail requests when only the list permission is granted", () => {
    const data = vi.spyOn(ui, "useData");
    setup(["user:list"], "/settings/users/example");
    expect(
        screen.getByRole("heading", { name: "Zugriff nicht erlaubt" }),
    ).toBeVisible();
    expect(data).not.toHaveBeenCalled();
});
it("redirects legacy administration links into the permission-filtered settings", () => {
    setup(["user:list"], "/administration/users", ["user_admin"]);
    expect(screen.getByRole("link", { name: "Benutzer" })).toHaveAttribute(
        "href",
        "/settings/users",
    );
    expect(
        screen.queryByRole("link", { name: "Zentrale SMTP-Einstellungen" }),
    ).not.toBeInTheDocument();
});
it("opens notification preferences by default when permitted", async () => {
    setup(["notification:read", "notification:preferences:update"]);
    expect(
        await screen.findByRole("heading", {
            name: "Benachrichtigungspräferenzen",
        }),
    ).toBeVisible();
});
it("keeps account settings available without administrative permissions", () => {
    setup([], "/settings/account");
    expect(screen.getByRole("link", { name: "Kontosicherheit" })).toBeVisible();
    for (const name of [
        "Benutzer",
        "Rollen",
        "Instanzeinstellungen",
        "Server",
        "Gruppen",
    ])
        expect(screen.queryByRole("link", { name })).not.toBeInTheDocument();
});
