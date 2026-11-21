import { afterEach, expect, it, vi } from "vitest";
import {
    act,
    cleanup,
    fireEvent,
    render,
    screen,
} from "@testing-library/react";
import { MemoryRouter, NavLink, useLocation } from "react-router-dom";
import { z } from "zod";
import * as client from "../src/api";
import { useData } from "../src/ui";
import FindingCountBadge from "../src/FindingCountBadge";
vi.mock("../src/auth", () => ({
    useAuth: () => ({
        identity: {
            permissions: ["finding:read"],
            privateKey: crypto.randomUUID(),
        },
    }),
}));
import {
    FINDINGS_CHANGED,
    FINDINGS_REFRESH,
    FINDINGS_REFRESH_INTERVAL,
    refreshFindingNavigation,
} from "../src/finding-refresh";
const schema = z.object({ value: z.string() });
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.useRealTimers();
});
function View({
    live = true,
    changes = false,
}: {
    live?: boolean;
    changes?: boolean;
}) {
    const location = useLocation();
    const result = useData(
        "/api/v1/findings" + location.search,
        schema,
        live
            ? {
                  refreshInterval: FINDINGS_REFRESH_INTERVAL,
                  refreshEvent: FINDINGS_REFRESH,
              }
            : changes
              ? { changeEvent: FINDINGS_CHANGED }
              : {},
    );
    return (
        <>
            <NavLink
                to="/findings"
                onClick={(event) =>
                    refreshFindingNavigation(event, location.pathname)
                }
            >
                Findings
            </NavLink>
            <p data-testid="url">{location.pathname + location.search}</p>
            <p data-testid="data">{result.data?.value ?? "loading"}</p>
            {result.error && <p role="alert">failed</p>}
        </>
    );
}
async function setup(live = true) {
    await act(async () => {
        render(
            <MemoryRouter
                initialEntries={["/findings?priority=high&offset=25"]}
            >
                <View live={live} />
            </MemoryRouter>,
        );
    });
}
it("updates findings periodically while keeping the visible list during the next request", async () => {
    vi.useFakeTimers();
    let finish: ((value: { value: string }) => void) | undefined;
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValueOnce({ value: "old" })
        .mockImplementationOnce(
            () =>
                new Promise((resolve) => {
                    finish = resolve;
                }),
        );
    await setup();
    await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
    });
    expect(calls).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("data")).toHaveTextContent("old");
    await act(async () => {
        finish?.({ value: "new" });
    });
    expect(screen.getByTestId("data")).toHaveTextContent("new");
});
it("refreshes immediately on a repeated findings click and preserves filters and pagination", async () => {
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValueOnce({ value: "old" })
        .mockResolvedValue({ value: "new" });
    await setup();
    await act(async () => {
        fireEvent.click(screen.getByRole("link", { name: "Findings" }));
    });
    expect(screen.getByTestId("data")).toHaveTextContent("new");
    expect(screen.getByTestId("url")).toHaveTextContent(
        "/findings?priority=high&offset=25",
    );
    expect(calls).toHaveBeenCalledTimes(2);
    expect(
        calls.mock.calls.every(
            ([path]) => path === "/api/v1/findings?priority=high&offset=25",
        ),
    ).toBe(true);
});
it("keeps the previous findings on connection errors and retries the next poll", async () => {
    vi.useFakeTimers();
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValueOnce({ value: "old" })
        .mockRejectedValueOnce(new Error("offline"))
        .mockResolvedValue({ value: "recovered" });
    await setup();
    await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
    });
    expect(screen.getByTestId("data")).toHaveTextContent("old");
    expect(screen.getByRole("alert")).toBeVisible();
    await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
    });
    expect(screen.getByTestId("data")).toHaveTextContent("recovered");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(calls).toHaveBeenCalledTimes(3);
});
it("does not overlap slow requests and cancels polling and refresh listeners on unmount", async () => {
    vi.useFakeTimers();
    let finish: ((value: { value: string }) => void) | undefined;
    const calls = vi.spyOn(client, "api").mockImplementation(
        () =>
            new Promise((resolve) => {
                finish = resolve;
            }),
    );
    await setup();
    await act(async () => {
        await vi.advanceTimersByTimeAsync(30000);
    });
    expect(calls).toHaveBeenCalledTimes(1);
    cleanup();
    expect(calls.mock.calls[0][2]?.signal?.aborted).toBe(true);
    await act(async () => {
        finish?.({ value: "late" });
        window.dispatchEvent(new Event(FINDINGS_REFRESH));
        await vi.advanceTimersByTimeAsync(30000);
    });
    expect(calls).toHaveBeenCalledTimes(1);
});
it("leaves other data views on manual refresh unless polling is explicitly enabled", async () => {
    vi.useFakeTimers();
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValue({ value: "manual" });
    await setup(false);
    await act(async () => {
        await vi.advanceTimersByTimeAsync(30000);
    });
    expect(calls).toHaveBeenCalledTimes(1);
});
it("retains modified-click browser navigation behavior", () => {
    const event = {
        button: 0,
        ctrlKey: true,
        preventDefault: vi.fn(),
    } as unknown as Parameters<typeof refreshFindingNavigation>[0];
    expect(refreshFindingNavigation(event, "/findings")).toBe(false);
    expect(event.preventDefault).not.toHaveBeenCalled();
});

it("also refreshes a findings URL with a trailing slash", () => {
    const event = {
        button: 0,
        preventDefault: vi.fn(),
    } as unknown as Parameters<typeof refreshFindingNavigation>[0];
    expect(refreshFindingNavigation(event, "/findings/")).toBe(true);
    expect(event.preventDefault).toHaveBeenCalledOnce();
});

it("automatically fills an empty findings view when a new finding is detected by the badge", async () => {
    vi.useFakeTimers();
    let counts = 0;
    let lists = 0;
    vi.spyOn(client, "api").mockImplementation(async (path) => {
        if (path === "/api/v1/findings/active-count")
            return { count: ++counts === 1 ? 0 : 1 };
        return { value: ++lists === 1 ? "empty" : "new finding" };
    });
    await act(async () => {
        render(
            <>
                <FindingCountBadge />
                <MemoryRouter initialEntries={["/findings"]}>
                    <View live={false} changes />
                </MemoryRouter>
            </>,
        );
    });
    expect(screen.getByTestId("data")).toHaveTextContent("empty");
    await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
    });
    expect(screen.getByLabelText("1 aktuelles Finding")).toBeVisible();
    expect(screen.getByTestId("data")).toHaveTextContent("new finding");
    expect(lists).toBe(2);
});
