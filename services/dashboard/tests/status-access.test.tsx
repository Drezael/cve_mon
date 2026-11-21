import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import StatusPage from "../src/status";
import * as ui from "../src/ui";
const identity = vi.hoisted(() => ({
    roles: ["user"],
    permissions: [
        "deployment:status:read",
        "deployment:diagnostics:read",
        "deployment:service:restart",
    ],
}));
vi.mock("../src/auth", () => ({ useAuth: () => ({ identity }) }));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
it.each(["user", "user_admin", "security_analyst", "viewer"])(
    "rejects %s even with status permissions before fetching data",
    (role) => {
        identity.roles = [role];
        const data = vi.spyOn(ui, "useData");
        render(
            <MemoryRouter initialEntries={["/status/services/api"]}>
                <Routes>
                    <Route path="/status/*" element={<StatusPage />} />
                </Routes>
            </MemoryRouter>,
        );
        expect(
            screen.getByRole("heading", {
                name: "Statuszugriff nicht erlaubt",
            }),
        ).toBeVisible();
        expect(data).not.toHaveBeenCalled();
    },
);
it("allows an admin to request the status overview", () => {
    identity.roles = ["admin", "user"];
    const data = vi
        .spyOn(ui, "useData")
        .mockReturnValue({ data: null, error: null, reload: vi.fn() });
    render(
        <MemoryRouter initialEntries={["/status"]}>
            <Routes>
                <Route path="/status/*" element={<StatusPage />} />
            </Routes>
        </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Systemstatus" })).toBeVisible();
    expect(data).toHaveBeenCalled();
});
