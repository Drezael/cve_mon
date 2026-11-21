import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import * as client from "../src/api";
import WorkflowControl from "../src/pages/WorkflowControl";
const auth = vi.hoisted(() => ({
    permissions: ["role:assign:privileged"],
    privateKey: crypto.randomUUID(),
}));
vi.mock("../src/auth", () => ({ useAuth: () => ({ identity: auth }) }));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    auth.permissions = ["role:assign:privileged"];
});
const snapshot = {
    enabled: true,
    auto_updates: false,
    update_interval: 1800,
    next_update_at: "2026-11-14T12:00:00Z",
    can_manage: true,
    stages: [
        {
            stage: "import",
            waiting: 3,
            queued: 0,
            running: 0,
            failed: 0,
            last_release: null,
        },
    ],
    runs: [],
};
it("restricts the administrator controls to administrators", () => {
    auth.permissions = ["cve:read"];
    const calls = vi.spyOn(client, "api");
    const view = render(<WorkflowControl />);
    expect(view.container).toBeEmptyDOMElement();
    expect(calls).not.toHaveBeenCalled();
});
it("shows waiting work and persists the selected automatic update schedule", async () => {
    const calls = vi.spyOn(client, "api").mockResolvedValue(snapshot);
    render(<WorkflowControl />);
    await screen.findByText("Pausiert");
    expect(screen.getAllByText("3")[0]).toBeInTheDocument();
    fireEvent.click(
        screen.getByRole("checkbox", {
            name: "Automatische Updates aktivieren",
        }),
    );
    fireEvent.change(screen.getByRole("combobox", { name: "Prüfintervall" }), {
        target: { value: "900" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Zeitplan speichern" }));
    await waitFor(() =>
        expect(calls).toHaveBeenCalledWith(
            "/api/v1/dashboard/orchestration/settings",
            expect.anything(),
            {
                method: "PUT",
                body: { auto_updates: true, update_interval: 900 },
            },
        ),
    );
});
