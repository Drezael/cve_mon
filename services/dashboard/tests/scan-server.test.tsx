import { afterEach, it, expect, vi } from "vitest";
import {
    cleanup,
    render,
    screen,
    fireEvent,
    waitFor,
} from "@testing-library/react";
import ScanServer from "../src/ScanServer";
import * as client from "../src/api";
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
it("enqueues a scan with an idempotency key and reports acceptance", async () => {
    const api = vi
        .spyOn(client, "api")
        .mockResolvedValue({
            job_id: "job",
            snapshot_id: "snapshot",
            state: "queued",
        });
    render(<ScanServer id="server" enabled />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() =>
        expect(screen.getByRole("status")).toHaveTextContent(/n8n/),
    );
    expect(api).toHaveBeenCalledWith(
        "/api/v1/dashboard/servers/server/scan",
        expect.anything(),
        expect.objectContaining({
            method: "POST",
            idempotencyKey: expect.any(String),
        }),
    );
});
it("does not enqueue for a read-only server", () => {
    const api = vi.spyOn(client, "api");
    render(<ScanServer id="server" enabled={false} />);
    expect(screen.getByRole("button")).toBeDisabled();
    fireEvent.click(screen.getByRole("button"));
    expect(api).not.toHaveBeenCalled();
});
it("preserves the key after a failed request without retrying automatically", async () => {
    const api = vi.spyOn(client, "api").mockRejectedValue(new Error("offline"));
    render(<ScanServer id="server" enabled />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() =>
        expect(screen.getByRole("status")).toHaveTextContent("offline"),
    );
    expect(api).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(api).toHaveBeenCalledTimes(2));
    expect(api.mock.calls[0][2]?.idempotencyKey).toBe(
        api.mock.calls[1][2]?.idempotencyKey,
    );
});
