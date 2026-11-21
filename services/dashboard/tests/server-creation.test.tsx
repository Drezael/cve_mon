import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import ServerCreation, { CreateServerButton } from "../src/ServerCreation";
import * as client from "../src/api";
import { useLocale, t, setLocale } from "../src/i18n";
function LanguageSwitcher() {
    const locale = useLocale();
    return (
        <select
            aria-label={t("Sprache")}
            value={locale}
            onChange={(e) => setLocale(e.target.value as "de" | "en")}
        >
            <option value="de">Deutsch</option>
            <option value="en">English</option>
        </select>
    );
}
const auth = vi.hoisted(() => ({
    permissions: ["server:create", "server:inventory:manage"],
}));
vi.mock("../src/auth", () => ({ useAuth: () => ({ identity: auth }) }));
beforeEach(() => {
    auth.permissions = ["server:create", "server:inventory:manage"];
    HTMLDialogElement.prototype.showModal = function () {
        this.open = true;
    };
    HTMLDialogElement.prototype.close = function () {
        this.open = false;
    };
});
afterEach(() => {
    cleanup();
    setLocale("de");
    localStorage.clear();
    vi.restoreAllMocks();
});
function setup(showLanguage = false) {
    const calls = vi.spyOn(client, "api").mockImplementation(async (path) => {
        if (path === "/api/v1/dashboard/admin/servers")
            return { id: "be872b3c-7803-4df8-95cc-74df8db948ee" };
        return {
            items: [],
            total: 0,
            limit: 25,
            offset: 0,
            max_bytes: 10485760,
            schema_versions: ["1.3"],
        };
    });
    render(
        <>
            {showLanguage && <LanguageSwitcher />}
            <RouterProvider
                router={createMemoryRouter(
                    [
                        {
                            path: "/servers",
                            element: (
                                <>
                                    <h1>Serverübersicht</h1>
                                    <CreateServerButton />
                                </>
                            ),
                        },
                        { path: "/servers/new", element: <ServerCreation /> },
                        {
                            path: "/servers/manage/:id",
                            element: <h1>Server angelegt</h1>,
                        },
                    ],
                    { initialEntries: ["/servers"] },
                )}
            />
        </>,
    );
    return calls;
}
it("opens the server form directly with an optional inventory input and no selection dialog", async () => {
    const calls = setup();
    fireEvent.click(screen.getByRole("button", { name: "Server anlegen" }));
    expect(await screen.findByLabelText("Serverbezeichnung")).toBeVisible();
    expect(
        screen.getByRole("heading", { name: "Server anlegen" }),
    ).toBeVisible();
    expect(screen.getByLabelText("JSON-Datei")).toBeVisible();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
});
it("saves a manual server only after explicit saving and reauthentication", async () => {
    const calls = setup();
    fireEvent.click(screen.getByRole("button", { name: "Server anlegen" }));
    fireEvent.change(await screen.findByLabelText("Serverbezeichnung"), {
        target: { value: "Mein Server" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Server speichern" }));
    expect(
        screen.getByRole("dialog", { name: "Identität erneut bestätigen" }),
    ).toBeVisible();
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
    fireEvent.change(screen.getByLabelText("Aktuelles Passwort"), {
        target: { value: "fixture-value" },
    });
    fireEvent.click(
        screen.getByRole("button", {
            name: "Identität bestätigen und speichern",
        }),
    );
    await waitFor(() =>
        expect(
            screen.getByRole("heading", { name: "Serverübersicht" }),
        ).toBeVisible(),
    );
    const saved = calls.mock.calls.find(
        ([path]) => path === "/api/v1/dashboard/admin/servers",
    );
    expect(saved?.[2]?.body).toMatchObject({
        display_name: "Mein Server",
        criticality: "medium",
        exposure: "unknown",
    });
});
it("requires an inventory when only inventory onboarding is permitted", async () => {
    auth.permissions = ["server:inventory:manage"];
    setup();
    fireEvent.click(screen.getByRole("button", { name: "Server anlegen" }));
    fireEvent.change(await screen.findByLabelText("Serverbezeichnung"), {
        target: { value: "Manuelle Eingabe" },
    });
    expect(
        screen.getByRole("button", { name: "Server speichern" }),
    ).toBeDisabled();
    expect(screen.getByLabelText("JSON-Datei")).toBeVisible();
});
it("does not offer server creation to read-only users", () => {
    auth.permissions = ["server:read"];
    setup();
    expect(
        screen.queryByRole("button", { name: "Server anlegen" }),
    ).not.toBeInTheDocument();
});

it("preserves the unsaved server form and makes no request when changing language", async () => {
    const calls = setup(true);
    fireEvent.click(screen.getByRole("button", { name: "Server anlegen" }));
    const input = await screen.findByLabelText("Serverbezeichnung");
    fireEvent.change(input, { target: { value: "Mein Server" } });
    const before = calls.mock.calls.length;
    fireEvent.change(screen.getByLabelText("Sprache"), {
        target: { value: "en" },
    });
    expect(screen.getByLabelText("Server name")).toBe(input);
    expect(input).toHaveValue("Mein Server");
    expect(
        screen.getByRole("heading", { name: "Create server" }),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Save server" })).toBeVisible();
    expect(screen.getByLabelText("JSON file")).toBeVisible();
    expect(calls.mock.calls).toHaveLength(before);
    fireEvent.change(screen.getByLabelText("Language"), {
        target: { value: "de" },
    });
    expect(screen.getByLabelText("Serverbezeichnung")).toBe(input);
    expect(input).toHaveValue("Mein Server");
});
