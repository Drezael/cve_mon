import { afterEach, expect, it, vi } from "vitest";
import {
    act,
    cleanup,
    render,
    screen,
    waitFor,
    fireEvent,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import * as client from "../src/api";
import Board from "../src/dashboards/Board";
import { DashboardEditorPage } from "../src/dashboards";
import {
    configSchema,
    type DashboardConfig,
    widgetQuery,
} from "../src/dashboards/contracts";
const identity = vi.hoisted(() => ({
    privateKey: crypto.randomUUID(),
    permissions: ["server:read", "finding:read", "security:overview:read"],
}));
vi.mock("../src/auth", () => ({ useAuth: () => ({ identity }) }));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.useRealTimers();
    identity.permissions = [
        "server:read",
        "finding:read",
        "security:overview:read",
    ];
});
const config = (widgets: DashboardConfig["widgets"]) =>
    configSchema.parse({
        version: 1,
        title: "Private",
        description: "",
        layout: { columns: 2 },
        refresh_interval_seconds: 0,
        widgets,
    });
function display(element: React.ReactNode, path = "/") {
    const router = createMemoryRouter([{ path, element }], {
        initialEntries: [path],
    });
    render(<RouterProvider router={router} />);
}
it("shares the overview request across metrics and renders notes as text", async () => {
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValue({ active_servers: 3, open_findings: 8 });
    const data = config([
        {
            id: "count",
            type: "metric",
            title: "Servers",
            metric: "active_servers",
            span: 1,
        },
        {
            id: "open",
            type: "metric",
            title: "Findings",
            metric: "open_findings",
            span: 1,
        },
        {
            id: "note",
            type: "text",
            title: "Note",
            text: "<img src=x onerror=alert(1)>",
            span: 2,
        },
    ]);
    display(<Board config={data} />);
    expect(await screen.findByText("8")).toBeVisible();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeVisible();
    expect(document.querySelector("img")).toBeNull();
    expect(calls).toHaveBeenCalledTimes(1);
});
it("isolates unavailable widgets and does not fetch data without permission", () => {
    identity.permissions = ["server:read"];
    const calls = vi.spyOn(client, "api");
    display(
        <Board
            config={config([
                {
                    id: "metric",
                    type: "metric",
                    title: "Restricted count",
                    metric: "open_findings",
                    span: 1,
                },
                {
                    id: "text",
                    type: "text",
                    title: "Notes",
                    text: "Still visible",
                    span: 1,
                },
            ])}
        />,
    );
    expect(
        screen.getByText("Keine Berechtigung für dieses Widget."),
    ).toBeVisible();
    expect(screen.getByText("Still visible")).toBeVisible();
    expect(calls).not.toHaveBeenCalled();
});
it("imports a YAML file as a draft and validates without persisting it", async () => {
    const checked = config([
        {
            id: "text",
            type: "text",
            title: "Notes",
            text: "Preview content",
            span: 1,
        },
    ]);
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValue({ valid: true, config: checked, errors: [] });
    display(<DashboardEditorPage />, "/dashboards/new");
    const file = new File(
        ["version: 1\ntitle: Imported\nwidgets: []\n"],
        "board.yaml",
        { type: "application/yaml" },
    );
    Object.defineProperty(file, "text", {
        value: async () => "version: 1\ntitle: Imported\nwidgets: []\n",
    });
    fireEvent.change(screen.getByLabelText("YAML-Datei importieren"), {
        target: { files: [file] },
    });
    await waitFor(() =>
        expect(screen.getByLabelText("Dashboard-YAML")).toHaveValue(
            "version: 1\ntitle: Imported\nwidgets: []\n",
        ),
    );
    expect(calls).not.toHaveBeenCalled();
    fireEvent.click(
        screen.getByRole("button", { name: "Prüfen und Vorschau" }),
    );
    expect(await screen.findByText("Preview content")).toBeVisible();
    expect(calls).toHaveBeenCalledTimes(1);
    expect(calls).toHaveBeenCalledWith(
        expect.stringContaining("/validate"),
        expect.anything(),
        expect.objectContaining({ method: "POST" }),
    );
});
it("keeps the YAML draft when validation fails", async () => {
    vi.spyOn(client, "api").mockResolvedValue({
        valid: false,
        config: null,
        errors: ["Duplicate YAML key at line 4"],
    });
    display(<DashboardEditorPage />, "/dashboards/new");
    fireEvent.change(screen.getByLabelText("Dashboard-YAML"), {
        target: { value: "title: A\ntitle: B" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Speichern" }));
    expect(
        await screen.findByText("Duplicate YAML key at line 4"),
    ).toBeVisible();
    expect(screen.getByLabelText("Dashboard-YAML")).toHaveValue(
        "title: A\ntitle: B",
    );
});
it("encodes filters without dropping explicit false values", () => {
    const query = widgetQuery(
        { kev: false, search: "a&b", group_id: null },
        10,
    );
    expect(query.get("kev")).toBe("false");
    expect(query.get("search")).toBe("a&b");
    expect(query.has("group_id")).toBe(false);
});

it("keeps editing enabled when validation is temporarily unavailable before saving", async () => {
    const calls = vi
        .spyOn(client, "api")
        .mockRejectedValue(new client.ApiError(503));
    display(<DashboardEditorPage />, "/dashboards/new");
    fireEvent.click(screen.getByRole("button", { name: "Speichern" }));
    await screen.findByRole("alert");
    expect(screen.getByLabelText("Dashboard-YAML")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Speichern" })).toBeEnabled();
    expect(calls).toHaveBeenCalledTimes(1);
    expect(calls).toHaveBeenCalledWith(
        expect.stringContaining("/validate"),
        expect.anything(),
        expect.anything(),
    );
});

it("stages table reads to avoid sending all widget queries in one burst", async () => {
    vi.useFakeTimers();
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValue({ items: [], total: 0, limit: 10, offset: 0 });
    display(
        <Board
            config={config([
                {
                    id: "first",
                    type: "servers",
                    title: "First",
                    limit: 10,
                    sort: "name",
                    filters: {},
                    span: 1,
                },
                {
                    id: "second",
                    type: "servers",
                    title: "Second",
                    limit: 10,
                    sort: "name",
                    filters: {},
                    span: 1,
                },
            ])}
        />,
    );
    await act(async () => {
        await Promise.resolve();
    });
    expect(calls).toHaveBeenCalledTimes(1);
    await act(async () => {
        await vi.advanceTimersByTimeAsync(600);
    });
    expect(calls).toHaveBeenCalledTimes(2);
});

it("opens a save-as dialog for an unchanged shared dashboard and creates a copy", async () => {
    HTMLDialogElement.prototype.showModal = function () {
        this.open = true;
    };
    HTMLDialogElement.prototype.close = function () {
        this.open = false;
    };
    const data = config([]);
    const original = {
        id: "shared",
        title: "Shared",
        yaml: "version: 1\ntitle: Shared\nwidgets: []\n",
        config: data,
        version: 4,
        can_edit: false,
        owner_username: "owner",
        created_at: "2026-11-19T00:00:00Z",
        updated_at: "2026-11-19T00:00:00Z",
    };
    const calls = vi
        .spyOn(client, "api")
        .mockImplementation(async (path) => {
            if (path.endsWith("/validate"))
                return { valid: true, config: data, errors: [] };
            if (path.endsWith("/copy"))
                return { ...original, id: "copied", can_edit: true };
            return original;
        });
    const router = createMemoryRouter(
        [
            { path: "/dashboards/:id/edit", element: <DashboardEditorPage /> },
            { path: "/dashboards/copied", element: <h1>Saved copy</h1> },
        ],
        { initialEntries: ["/dashboards/shared/edit"] },
    );
    render(<RouterProvider router={router} />);
    await screen.findByLabelText("Dashboard-YAML");
    fireEvent.click(screen.getByRole("button", { name: "Speichern" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.submit(dialog.querySelector("form")!);
    await screen.findByRole("heading", { name: "Saved copy" });
    expect(
        calls.mock.calls.some(
            ([path, , options]) =>
                path.endsWith("/copy") && options?.method === "POST",
        ),
    ).toBe(true);
    expect(
        calls.mock.calls.some(([, , options]) => options?.method === "PUT"),
    ).toBe(false);
});
