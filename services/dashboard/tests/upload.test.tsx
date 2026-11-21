import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import * as client from "../src/api";
import Upload from "../src/admin/Upload";

afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
function setup(manualAllowed = false) {
    const calls = vi
        .spyOn(client, "api")
        .mockImplementation(async (path, _schema, options) => {
            if (options?.method === "POST")
                return {
                    submission_id: crypto.randomUUID(),
                    server_id: crypto.randomUUID(),
                    status: "accepted",
                };
            if (path.includes("/uploads/"))
                return { processing: { status: "completed" } };
            return {
                items: [],
                total: 0,
                limit: 25,
                offset: 0,
                max_bytes: 10485760,
                schema_versions: ["1.0", "1.1", "1.2", "1.3"],
            };
        });
    render(
        <RouterProvider
            router={createMemoryRouter(
                [
                    { path: "/servers", element: <h1>Serverübersicht</h1> },
                    {
                        path: "/servers/upload",
                        element: <Upload manualAllowed={manualAllowed} />,
                    },
                    {
                        path: "/servers/new",
                        element: <Upload manualAllowed={manualAllowed} />,
                    },
                ],
                { initialEntries: ["/servers/new"] },
            )}
        />,
    );
    return calls;
}
function contents(hostname = "example-server") {
    return JSON.stringify({
        schema_version: "1.3",
        inventory_id: crypto.randomUUID(),
        host: { monitoring_id: crypto.randomUUID(), hostname },
        packages: { items: [{ name: "example-package", version: "1.2" }] },
        containers: { items: [{ name: "example-container" }] },
    });
}
function file(raw: string) {
    const result = new File([raw], "server.json", { type: "application/json" });
    Object.defineProperty(result, "arrayBuffer", {
        value: async () => new TextEncoder().encode(raw).buffer,
    });
    return result;
}
it("loads the complete inventory locally and submits its exact contents only after explicit save", async () => {
    const calls = setup();
    const raw = contents();
    fireEvent.change(await screen.findByLabelText("JSON-Datei"), {
        target: { files: [file(raw)] },
    });
    expect(
        await screen.findByText("Vollständig geladen · Noch nicht gespeichert"),
    ).toBeVisible();
    expect(screen.getByText("example-server", { exact: true })).toBeVisible();
    expect(screen.getByText(raw)).toBeInTheDocument();
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Server speichern" }));
    await waitFor(() =>
        expect(
            calls.mock.calls.filter(
                ([, , options]) => options?.method === "POST",
            ),
        ).toHaveLength(1),
    );
    expect(
        await screen.findByRole("heading", { name: "Serverübersicht" }),
    ).toBeVisible();
    const body = calls.mock.calls.find(
        ([, , options]) => options?.method === "POST",
    )?.[2]?.body as FormData;
    expect(body.has("server_id")).toBe(false);
    const uploaded = body.get("file") as Blob;
    const actual = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(uploaded);
    });
    expect(actual).toBe(raw);
});
it("rejects invalid JSON before saving or creating a server", async () => {
    const calls = setup();
    fireEvent.change(await screen.findByLabelText("JSON-Datei"), {
        target: { files: [file("{invalid")] },
    });
    expect(await screen.findByRole("alert")).toHaveTextContent(
        "gültiges UTF-8 und JSON",
    );
    expect(
        screen.getByRole("button", { name: "Server speichern" }),
    ).toBeDisabled();
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
});
it("discards a loaded inventory without creating any server", async () => {
    const calls = setup();
    fireEvent.change(await screen.findByLabelText("JSON-Datei"), {
        target: { files: [file(contents())] },
    });
    await screen.findByText("Vollständig geladen · Noch nicht gespeichert");
    fireEvent.click(screen.getByRole("button", { name: "Inventar verwerfen" }));
    expect(
        screen.queryByRole("region", { name: "Inventarvorschau" }),
    ).not.toBeInTheDocument();
    expect(
        screen.getByRole("button", { name: "Server speichern" }),
    ).toBeDisabled();
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
});
it("ignores a slow read of a previously selected file", async () => {
    const calls = setup();
    let finish: ((value: ArrayBuffer) => void) | undefined;
    const old = new File(["old"], "old.json");
    Object.defineProperty(old, "arrayBuffer", {
        value: () =>
            new Promise<ArrayBuffer>((resolve) => {
                finish = resolve;
            }),
    });
    const input = await screen.findByLabelText("JSON-Datei");
    fireEvent.change(input, { target: { files: [old] } });
    expect(
        screen.getByRole("button", { name: "Server speichern" }),
    ).toBeDisabled();
    fireEvent.change(input, {
        target: { files: [file(contents("new-host"))] },
    });
    expect(await screen.findByText("new-host", { exact: true })).toBeVisible();
    finish?.(new TextEncoder().encode(contents("old-host")).buffer);
    await waitFor(() =>
        expect(screen.getByText("new-host", { exact: true })).toBeVisible(),
    );
    expect(
        screen.queryByText("old-host", { exact: true }),
    ).not.toBeInTheDocument();
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
});

it("prefills the shared server fields and keeps edited metadata separate from protected inventory", async () => {
    const calls = setup();
    const raw = contents();
    fireEvent.change(await screen.findByLabelText("JSON-Datei"), {
        target: { files: [file(raw)] },
    });
    await screen.findByText("Vollständig geladen · Noch nicht gespeichert");
    expect(screen.getByLabelText("Serverbezeichnung")).toHaveValue(
        "example-server",
    );
    fireEvent.change(screen.getByLabelText("Serverbezeichnung"), {
        target: { value: "Mein Server" },
    });
    fireEvent.change(screen.getByLabelText("Beschreibung"), {
        target: { value: "Eigene Beschreibung" },
    });
    fireEvent.change(screen.getByLabelText("Umgebung"), {
        target: { value: "Produktion" },
    });
    fireEvent.change(screen.getByLabelText("Kritikalität"), {
        target: { value: "high" },
    });
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Server speichern" }));
    await waitFor(() =>
        expect(
            calls.mock.calls.filter(
                ([, , options]) => options?.method === "POST",
            ),
        ).toHaveLength(1),
    );
    const body = calls.mock.calls.find(
        ([, , options]) => options?.method === "POST",
    )?.[2]?.body as FormData;
    expect(JSON.parse(String(body.get("server_metadata")))).toMatchObject({
        display_name: "Mein Server",
        description: "Eigene Beschreibung",
        environment: "Produktion",
        criticality: "high",
    });
    const uploaded = body.get("file") as Blob;
    const actual = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(uploaded);
    });
    expect(actual).toBe(raw);
});

it("allows editing hardware while protecting identifiers and software versions", async () => {
    const calls = setup();
    const value = JSON.parse(contents());
    value.hardware = { cpu_count: 2, memory_mb: 2048 };
    fireEvent.change(await screen.findByLabelText("JSON-Datei"), {
        target: { files: [file(JSON.stringify(value))] },
    });
    await screen.findByText("Vollständig geladen · Noch nicht gespeichert");
    fireEvent.click(screen.getByText("Hardware bearbeiten"));
    fireEvent.change(screen.getByLabelText("CPU-Anzahl"), {
        target: { value: "4" },
    });
    fireEvent.click(screen.getByText("Servererkennung", { exact: true }));
    const monitoring = await screen.findByLabelText("host.monitoring_id");
    expect(monitoring).toHaveAttribute("readonly");
    fireEvent.change(monitoring, { target: { value: crypto.randomUUID() } });
    fireEvent.click(screen.getByRole("button", { name: "Server speichern" }));
    await waitFor(() =>
        expect(
            calls.mock.calls.filter(
                ([, , options]) => options?.method === "POST",
            ),
        ).toHaveLength(1),
    );
    const body = calls.mock.calls.find(
        ([, , options]) => options?.method === "POST",
    )?.[2]?.body as FormData;
    const uploaded = body.get("file") as Blob;
    const actual = JSON.parse(
        await new Promise<string>((resolve) => {
            const reader = new FileReader();
            reader.onload = () => resolve(String(reader.result));
            reader.readAsText(uploaded);
        }),
    );
    expect(actual.host).toEqual(value.host);
    expect(actual.packages).toEqual(value.packages);
    expect(actual.hardware).toEqual({ cpu_count: 4, memory_mb: 2048 });
});

it("preserves manually entered metadata when an optional inventory is loaded", async () => {
    const calls = setup(true);
    const input = await screen.findByLabelText("JSON-Datei");
    fireEvent.change(screen.getByLabelText("Beschreibung"), {
        target: { value: "Vorher eingegeben" },
    });
    fireEvent.change(screen.getByLabelText("Umgebung"), {
        target: { value: "Produktion" },
    });
    fireEvent.change(input, { target: { files: [file(contents())] } });
    await screen.findByText("Vollständig geladen · Noch nicht gespeichert");
    expect(screen.getByLabelText("Serverbezeichnung")).toHaveValue(
        "example-server",
    );
    expect(screen.getByLabelText("Beschreibung")).toHaveValue(
        "Vorher eingegeben",
    );
    expect(screen.getByLabelText("Umgebung")).toHaveValue("Produktion");
    expect(
        calls.mock.calls.filter(([, , options]) => options?.method === "POST"),
    ).toHaveLength(0);
});
