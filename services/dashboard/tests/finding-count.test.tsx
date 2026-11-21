import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import * as client from "../src/api";
import FindingCountBadge from "../src/FindingCountBadge";
const identity = vi.hoisted(() => ({
    privateKey: crypto.randomUUID(),
    permissions: ["finding:read"],
}));
vi.mock("../src/auth", () => ({ useAuth: () => ({ identity }) }));
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.useRealTimers();
    identity.permissions = ["finding:read"];
});
it("shows the active count and hides the badge once the count becomes zero", async () => {
    vi.useFakeTimers();
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValueOnce({ count: 3 })
        .mockResolvedValue({ count: 0 });
    await act(async () => {
        render(<FindingCountBadge />);
    });
    expect(screen.getByLabelText("3 aktuelle Findings")).toHaveTextContent("3");
    await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
    });
    expect(
        screen.queryByLabelText("3 aktuelle Findings"),
    ).not.toBeInTheDocument();
    expect(calls).toHaveBeenCalledTimes(2);
});
it("does not request finding counts without permission", () => {
    identity.permissions = [];
    const calls = vi.spyOn(client, "api");
    const view = render(<FindingCountBadge />);
    expect(view.container).toBeEmptyDOMElement();
    expect(calls).not.toHaveBeenCalled();
});

it("refreshes the finding badge immediately when findings are requested again", async () => {
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValueOnce({ count: 2 })
        .mockResolvedValue({ count: 4 });
    await act(async () => {
        render(<FindingCountBadge />);
    });
    await act(async () => {
        window.dispatchEvent(new Event("cve-findings-refresh"));
    });
    expect(screen.getByLabelText("4 aktuelle Findings")).toBeVisible();
    expect(calls).toHaveBeenCalledTimes(2);
});
