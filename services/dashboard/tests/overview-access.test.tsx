import { afterEach, it, expect, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Overview from "../src/pages/Overview";
import * as ui from "../src/ui";
const identity = vi.hoisted(() => ({
    roles: ["user"],
    permissions: ["security:overview:read", "cve:read", "cve:update"],
}));
vi.mock("../src/auth", () => ({ useAuth: () => ({ identity }) }));
vi.mock("../src/pages/CveDataStatus", () => ({
    default: () => <button>Database admin controls</button>,
}));
vi.mock("../src/pages/WorkflowControl", () => ({
    default: () => <button>Schedule admin controls</button>,
}));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
it.each(["user", "security_analyst", "user_admin"])(
    "renders data-only overview for %s despite update permissions",
    (role) => {
        identity.roles = [role];
        const data = vi
            .spyOn(ui, "useData")
            .mockReturnValue({ data: null, error: null, reload: vi.fn() });
        render(
            <MemoryRouter>
                <Overview />
            </MemoryRouter>,
        );
        expect(
            screen.queryByText("Database admin controls"),
        ).not.toBeInTheDocument();
        expect(
            screen.queryByText("Schedule admin controls"),
        ).not.toBeInTheDocument();
        expect(
            data.mock.calls.every(([path]) =>
                path.startsWith("/api/v1/dashboard/overview"),
            ),
        ).toBe(true);
    },
);
it("keeps full overview available to admin", () => {
    identity.roles = ["admin"];
    vi.spyOn(ui, "useData").mockReturnValue({
        data: null,
        error: null,
        reload: vi.fn(),
    });
    render(
        <MemoryRouter>
            <Overview />
        </MemoryRouter>,
    );
    expect(screen.getByText("Database admin controls")).toBeVisible();
    expect(screen.getByText("Schedule admin controls")).toBeVisible();
});
