import { afterEach, it, expect, vi } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { ResourceDetail } from "../src/admin/Resources";
import * as ui from "../src/ui";
vi.mock("../src/auth", () => ({
    useAuth: () => ({
        identity: { permissions: ["server:update", "server:inventory:manage"] },
    }),
}));
vi.mock("../src/ServerGroups", () => ({ AssignServerGroups: () => null }));
vi.mock("../src/admin/AnsibleSettings", () => ({ default: () => null }));
vi.mock("../src/DeleteServer", () => ({ default: () => null }));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
function open(canEdit = true) {
    vi.spyOn(ui, "useData").mockImplementation((path) => ({
        data: path.includes("/security/")
            ? { can_edit: canEdit }
            : {
                  id: "server",
                  version: 1,
                  display_name: "Test server",
                  description: "Notes",
                  environment: "prod",
                  criticality: "medium",
                  exposure: "internal",
              },
        error: null,
        reload: vi.fn(),
    }));
    const router = createMemoryRouter(
        [
            { path: "/servers/manage/:id", element: <ResourceDetail /> },
            { path: "/servers", element: <h1>Server overview</h1> },
        ],
        { initialEntries: ["/servers/manage/server"] },
    );
    render(<RouterProvider router={router} />);
    return router;
}
it("opens the populated edit form directly and returns to servers on cancel", async () => {
    const router = open();
    expect(screen.getByDisplayValue("Test server")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: /Abbrechen|Cancel/ }));
    expect(router.state.location.pathname).toBe("/servers");
});
it("does not expose an edit form to a read-only recipient", () => {
    open(false);
    expect(screen.getByRole("alert")).toBeVisible();
    expect(screen.queryByDisplayValue("Test server")).not.toBeInTheDocument();
});
