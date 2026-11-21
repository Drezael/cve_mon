import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import {
    render,
    screen,
    fireEvent,
    waitFor,
    cleanup,
    within,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider, Link } from "react-router-dom";
import { EditForm, type Mutation } from "../src/admin/Form";
import * as client from "../src/api";
import { serverCreateSchema, userCreateSchema } from "../src/admin/contracts";
beforeEach(() => {
    HTMLDialogElement.prototype.showModal = function () {
        this.open = true;
    };
    HTMLDialogElement.prototype.close = function () {
        this.open = false;
    };
});
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
function form(overrides: Partial<Mutation> = {}) {
    const done = vi.fn();
    const reload = vi.fn();
    const operation: Mutation = {
        title: "Server Beispiel ändern",
        path: "/api/v1/dashboard/admin/servers/example",
        method: "PATCH",
        version: 4,
        stepUp: false,
        fields: [{ key: "display_name", label: "Bezeichnung", required: true }],
        initial: { display_name: "Beispiel" },
        ...overrides,
    };
    const router = createMemoryRouter([
        {
            path: "/",
            element: (
                <>
                    <Link to="/away">Andere Ansicht</Link>
                    <EditForm
                        operation={operation}
                        onDone={done}
                        onCancel={() => {}}
                        onReload={reload}
                    />
                </>
            ),
        },
        { path: "/away", element: <h1>Andere Seite</h1> },
    ]);
    render(<RouterProvider router={router} />);
    return { done, reload };
}
describe("Administrative mutation boundary", () => {
    it("protects a prepared draft before editing its confirmation fields", async () => {
        form({ dirty: true });
        fireEvent.click(screen.getByRole("link", { name: "Andere Ansicht" }));
        expect(
            await screen.findByRole("dialog", {
                name: "Ungespeicherte Änderungen",
            }),
        ).toBeInTheDocument();
        fireEvent.click(
            screen.getByRole("button", { name: "Weiter bearbeiten" }),
        );
        expect(
            screen.getByRole("heading", { name: "Server Beispiel ändern" }),
        ).toBeInTheDocument();
        expect(
            screen.queryByRole("heading", { name: "Andere Seite" }),
        ).not.toBeInTheDocument();
    });
    it("uses the captured revision and only confirms actual responses", async () => {
        const call = vi
            .spyOn(client, "api")
            .mockResolvedValue({ id: "server", version: 5 });
        const { done } = form();
        fireEvent.change(screen.getByLabelText("Bezeichnung"), {
            target: { value: "Neu" },
        });
        fireEvent.click(screen.getByRole("button", { name: "Speichern" }));
        await waitFor(() =>
            expect(done).toHaveBeenCalledWith({ id: "server", version: 5 }),
        );
        expect(call).toHaveBeenCalledWith(
            "/api/v1/dashboard/admin/servers/example",
            expect.anything(),
            expect.objectContaining({
                method: "PATCH",
                version: 4,
                body: { display_name: "Neu" },
            }),
        );
    });
    it("retains input and blocks silent overwrite after a version conflict", async () => {
        vi.spyOn(client, "api").mockRejectedValue(new client.ApiError(412));
        const { done, reload } = form();
        fireEvent.change(screen.getByLabelText("Bezeichnung"), {
            target: { value: "Lokaler Entwurf" },
        });
        fireEvent.click(screen.getByRole("button", { name: "Speichern" }));
        await screen.findByRole("alert");
        expect(screen.getByLabelText("Bezeichnung")).toHaveValue(
            "Lokaler Entwurf",
        );
        expect(done).not.toHaveBeenCalled();
        fireEvent.click(
            screen.getByRole("button", { name: "Aktuellen Stand neu laden" }),
        );
        expect(reload).toHaveBeenCalledOnce();
    });
    it("requires critical confirmation before dispatch", async () => {
        const call = vi
            .spyOn(client, "api")
            .mockResolvedValue({ id: "server" });
        form({ critical: true });
        fireEvent.click(screen.getByRole("button", { name: "Speichern" }));
        const dialog = screen.getByRole("dialog");
        expect(call).not.toHaveBeenCalled();
        expect(dialog).toHaveTextContent("Server Beispiel ändern");
        fireEvent.click(
            within(dialog).getByRole("button", { name: "Abbrechen" }),
        );
        expect(call).not.toHaveBeenCalled();
    });
    it("prevents duplicate mutations and never reports unknown outcomes as success", async () => {
        let reject: (e: Error) => void = () => {};
        const call = vi.spyOn(client, "api").mockImplementation(
            () =>
                new Promise((_, r) => {
                    reject = r;
                }),
        );
        const { done } = form();
        const save = screen.getByRole("button", { name: "Speichern" });
        fireEvent.click(save);
        fireEvent.click(save);
        expect(call).toHaveBeenCalledOnce();
        reject(new client.ApiError(0));
        await screen.findByRole("alert");
        expect(done).not.toHaveBeenCalled();
        expect(
            screen.getByRole("button", { name: "Speichern" }),
        ).toBeDisabled();
    });
    it("blocks navigation with an unsaved draft", async () => {
        form();
        fireEvent.change(screen.getByLabelText("Bezeichnung"), {
            target: { value: "Nicht gespeichert" },
        });
        fireEvent.click(screen.getByRole("link", { name: "Andere Ansicht" }));
        const dialog = await screen.findByRole("dialog");
        expect(dialog).toHaveTextContent("Ungespeicherte Änderungen");
        expect(
            screen.queryByRole("heading", { name: "Andere Seite" }),
        ).not.toBeInTheDocument();
        fireEvent.click(
            within(dialog).getByRole("button", {
                name: "Änderungen verwerfen",
            }),
        );
        await screen.findByRole("heading", { name: "Andere Seite" });
    });
    it("does not accept arbitrary administrative create fields", () => {
        expect(
            userCreateSchema.safeParse({
                username: "user",
                display_name: "User",
                email: "user@example.test",
                is_admin: true,
            }).success,
        ).toBe(false);
        expect(
            serverCreateSchema.safeParse({
                request_id: "00000000-0000-4000-8000-000000000001",
                display_name: "Server",
                groups: ["unauthorized"],
            }).success,
        ).toBe(false);
    });
});

describe("Same-origin CSRF and version headers", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
        client.clearPrivate();
    });
    it("uses CSRF and exact If-Match for every supported write method", async () => {
        for (const method of ["PUT", "PATCH", "DELETE"] as const) {
            client.clearPrivate();
            const fetch = vi.fn(async (path: string) =>
                path.endsWith("/csrf")
                    ? new Response('{"csrf_token":"fixture-csrf"}')
                    : new Response(null, { status: 204 }),
            );
            vi.stubGlobal("fetch", fetch);
            await client.api(
                "/api/v1/dashboard/admin/roles/example",
                (await import("zod")).z.null(),
                { method, body: { reason: "Expliziter Test" }, version: 7 },
            );
            expect(fetch).toHaveBeenLastCalledWith(
                "/api/v1/dashboard/admin/roles/example",
                expect.objectContaining({
                    method,
                    credentials: "same-origin",
                    headers: expect.objectContaining({
                        "X-CSRF-Token": "fixture-csrf",
                        "If-Match": '"7"',
                    }),
                }),
            );
        }
    });
    it("does not retry a write after a transport failure", async () => {
        client.clearPrivate();
        const fetch = vi.fn(async (path: string) => {
            if (path.endsWith("/csrf"))
                return new Response('{"csrf_token":"fixture-csrf"}');
            throw new TypeError("network");
        });
        vi.stubGlobal("fetch", fetch);
        await expect(
            client.api(
                "/api/v1/dashboard/admin/roles/example",
                (await import("zod")).z.null(),
                { method: "DELETE", body: { version: 1 } },
            ),
        ).rejects.toMatchObject({ status: 0 });
        expect(fetch).toHaveBeenCalledTimes(2);
    });
});

it("accepts existing system roles with an unset description", async () => {
    const { rolesSchema } = await import("../src/admin/contracts");
    const roles = rolesSchema.parse([
        {
            id: "role-id",
            code: "admin",
            name: "Administrator",
            description: null,
            is_system: true,
            version: 1,
            permissions: [],
        },
    ]);
    expect(roles[0].description).toBe("");
});
