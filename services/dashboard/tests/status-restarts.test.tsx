import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
    within,
} from "@testing-library/react";
import Restarts, {
    RestartActions,
    StatusRefresh,
} from "../src/status/Restarts";
import { StatusOverview } from "../src/status";
import { MemoryRouter } from "react-router-dom";
import * as client from "../src/api";
import * as ui from "../src/ui";
const auth = vi.hoisted(() => ({
    permissions: ["deployment:service:restart"],
}));
vi.mock("../src/auth", () => ({
    useAuth: () => ({
        identity: {
            permissions: auth.permissions,
            privateKey: crypto.randomUUID(),
        },
    }),
}));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    auth.permissions = ["deployment:service:restart"];
});
const data = {
    items: [],
    targets: [
        {
            id: "importer",
            name: "CVE V5 Git-Import",
            container: "cve-processing",
        },
    ],
};
it("requires a reason and queues a process restart with an idempotency key", async () => {
    vi.spyOn(ui, "useData").mockReturnValue({
        data,
        error: null,
        reload: vi.fn(),
    });
    const call = vi
        .spyOn(client, "api")
        .mockResolvedValue({ id: crypto.randomUUID() });
    render(
        <Restarts>
            <RestartActions entityId="importer" />
        </Restarts>,
    );
    fireEvent.click(
        screen.getByRole("button", { name: "CVE V5 Git-Import neu starten" }),
    );
    expect(call).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toHaveTextContent(
        "Der Container wird nicht neu gestartet",
    );
    const confirm = screen.getByRole("button", {
        name: "Über n8n neu starten",
    });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Grund für den Neustart"), {
        target: { value: "Dienst reagiert nicht" },
    });
    fireEvent.click(confirm);
    await waitFor(() => expect(call).toHaveBeenCalledTimes(1));
    expect(call.mock.calls[0][0]).toBe(
        "/api/v1/status/services/importer/restart",
    );
    expect(call.mock.calls[0][2]?.idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);
    await screen.findByText(/n8n übernimmt die Freigabe/);
});
it("does not expose restart controls without the permission", () => {
    auth.permissions = [];
    render(
        <Restarts>
            <RestartActions entityId="importer" />
        </Restarts>,
    );
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
});
it("blocks a second restart while the existing command waits for n8n", () => {
    vi.spyOn(ui, "useData").mockReturnValue({
        data: {
            ...data,
            items: [
                {
                    id: crypto.randomUUID(),
                    service_id: "importer",
                    state: "waiting",
                    reason: "Recovery",
                    requested_at: new Date().toISOString(),
                    execution_id: null,
                    error_code: null,
                },
            ],
        },
        error: null,
        reload: vi.fn(),
    });
    render(
        <Restarts>
            <RestartActions entityId="importer" />
        </Restarts>,
    );
    expect(
        screen.getByRole("button", { name: "CVE V5 Git-Import neu starten" }),
    ).toBeDisabled();
});

it("refreshes restart status only on an explicit click", () => {
    vi.useFakeTimers();
    try {
        const reload = vi.fn();
        vi.spyOn(ui, "useData").mockReturnValue({ data, error: null, reload });
        render(
            <Restarts>
                <RestartActions entityId="importer" />
                <StatusRefresh onRefresh={() => {}} />
            </Restarts>,
        );
        vi.advanceTimersByTime(60000);
        expect(reload).not.toHaveBeenCalled();
        fireEvent.click(
            screen.getByRole("button", {
                name: "Status aktualisieren",
            }),
        );
        expect(reload).toHaveBeenCalledTimes(1);
    } finally {
        vi.useRealTimers();
    }
});

it("places restart actions inside the service and pipeline rows without a restart category", () => {
    const entry = (id: string, name: string, kind: "service" | "pipeline") => ({
        id,
        name,
        kind,
        schema_version: 1,
        state: "healthy",
        raw_state: "healthy",
        display_state: "healthy",
        observed_at: null,
        stale: false,
        maintenance_ids: [],
    });
    const overview = {
        schema_version: 1,
        state: "healthy",
        as_of: new Date().toISOString(),
        last_observation_at: null,
        coverage: { known: 2, total: 2 },
        active_incidents: 0,
        services: [
            entry("importer", "CVE V5 Git-Import", "service"),
            entry("postgres", "PostgreSQL", "service"),
        ],
        pipelines: [
            entry("pipeline-cve", "CVE V5 Import und Suchindex", "pipeline"),
            entry("pipeline-control", "Zentrale n8n-Steuerung", "pipeline"),
        ],
    };
    vi.spyOn(ui, "useData").mockImplementation((path) => ({
        data: path.endsWith("/admin/restarts") ? data : overview,
        error: null,
        reload: vi.fn(),
    }));
    render(
        <MemoryRouter>
            <StatusOverview />
        </MemoryRouter>,
    );
    const services = screen
        .getByRole("heading", { name: "Dienste" })
        .closest("section")!;
    const pipelines = screen
        .getByRole("heading", { name: "Verarbeitungspipelines" })
        .closest("section")!;
    expect(
        within(services).getByRole("button", {
            name: "CVE V5 Git-Import neu starten",
        }),
    ).toBeInTheDocument();
    expect(
        within(pipelines).getByRole("button", {
            name: "CVE V5 Git-Import neu starten",
        }),
    ).toBeInTheDocument();
    expect(
        screen.queryByRole("button", { name: "PostgreSQL neu starten" }),
    ).not.toBeInTheDocument();
    expect(
        screen.queryByRole("heading", { name: "Microservice neu starten" }),
    ).not.toBeInTheDocument();
    expect(
        screen.queryByText("Letzte Neustartaufträge"),
    ).not.toBeInTheDocument();
});

it.each([
    ["pipeline-inventory", "inventory"],
    ["pipeline-cve", "importer"],
    ["pipeline-matching", "matcher"],
    ["pipeline-notifications", "notification"],
    ["pipeline-control", null],
] as const)("offers at most one restart for %s", (entityId, primary) => {
    const targets = [
        "api",
        "inventory",
        "importer",
        "matcher",
        "findings",
        "dispatcher",
        "notification",
    ].map((id) => ({ id, name: id, container: "cve-processing" }));
    vi.spyOn(ui, "useData").mockReturnValue({
        data: { items: [], targets },
        error: null,
        reload: vi.fn(),
    });
    render(
        <Restarts>
            <RestartActions entityId={entityId} />
        </Restarts>,
    );
    expect(screen.queryAllByRole("button")).toHaveLength(primary ? 1 : 0);
    if (primary) {
        fireEvent.click(
            screen.getByRole("button", { name: primary + " neu starten" }),
        );
        expect(
            screen.getByRole("heading", { name: primary + " neu starten?" }),
        ).toBeInTheDocument();
    }
});
