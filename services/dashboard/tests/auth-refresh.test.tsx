import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, act } from "@testing-library/react";
import { StrictMode } from "react";
import * as client from "../src/api";
import { AuthProvider, useAuth } from "../src/auth";

afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
function Identity() {
    const { identity, checking } = useAuth();
    return <p>{checking ? "checking" : (identity?.state ?? "signed-out")}</p>;
}
it("an older failed session refresh cannot overwrite a newer authenticated identity", async () => {
    let older: ((reason: Error) => void) | undefined;
    let calls = 0;
    vi.spyOn(client, "clearPrivate").mockImplementation(() => {});
    vi.spyOn(client, "api").mockImplementation(async (path) => {
        if (path.endsWith("/session")) {
            calls++;
            if (calls === 1)
                return new Promise((_, reject) => {
                    older = reject;
                });
            return { state: "authenticated" };
        }
        return { user_id: "user", authorization_version: 1, permissions: [] };
    });
    render(
        <StrictMode>
            <AuthProvider>
                <Identity />
            </AuthProvider>
        </StrictMode>,
    );
    expect(await screen.findByText("authenticated")).toBeVisible();
    await act(async () => {
        older?.(new Error("Stale refresh aborted"));
    });
    expect(screen.getByText("authenticated")).toBeVisible();
});
