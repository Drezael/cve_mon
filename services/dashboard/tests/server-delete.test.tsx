import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
    within,
} from "@testing-library/react";
import * as client from "../src/api";
import DeleteServer from "../src/DeleteServer";
beforeEach(() => {
    HTMLDialogElement.prototype.showModal = function () {
        this.open = true;
    };
    HTMLDialogElement.prototype.close = function () {
        this.open = false;
    };
});
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});
it("requires confirmation and sends the server revision on deletion", async () => {
    const calls = vi.spyOn(client, "api").mockResolvedValue(undefined);
    const done = vi.fn();
    render(
        <DeleteServer
            server={{
                id: "server-id",
                display_name: "Demo",
                version: 7,
                can_delete: true,
            }}
            onDeleted={done}
        />,
    );
    fireEvent.click(
        screen.getByRole("button", { name: "Server Demo löschen" }),
    );
    expect(calls).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog", { name: "Server löschen" });
    fireEvent.click(
        within(dialog).getByRole("button", { name: "Server löschen" }),
    );
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
    expect(calls).toHaveBeenCalledWith(
        "/api/v1/dashboard/servers/server-id",
        expect.anything(),
        { method: "DELETE", version: 7, timeoutMs: 60000, idempotencyKey: expect.any(String) },
    );
});
it("hides deletion for servers the user cannot delete", () => {
    const view = render(
        <DeleteServer
            server={{
                id: "other",
                display_name: "Other",
                version: 1,
                can_delete: false,
            }}
            onDeleted={() => {}}
        />,
    );
    expect(view.container).toBeEmptyDOMElement();
});

it("checks a lost deletion response without issuing another DELETE", async () => {
    const calls = vi.spyOn(client, "api")
        .mockRejectedValueOnce(new client.ApiError(504))
        .mockResolvedValueOnce({ state: "completed" });
    const done = vi.fn();
    render(<DeleteServer server={{id:"demo",display_name:"Demo",version:1,can_delete:true}} onDeleted={done} />);
    fireEvent.click(screen.getByRole("button",{name:"Server Demo löschen"}));
    const dialog=screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button",{name:"Server löschen"}));
    await waitFor(()=>expect(within(dialog).getByRole("button",{name:"Status prüfen"})).toBeEnabled());
    expect(within(dialog).getByRole("button",{name:"Server löschen"})).toBeDisabled();
    const requestId=calls.mock.calls[0][2]?.idempotencyKey;
    fireEvent.click(within(dialog).getByRole("button",{name:"Status prüfen"}));
    await waitFor(()=>expect(done).toHaveBeenCalledOnce());
    expect(calls.mock.calls[1][0]).toBe(`/api/v1/dashboard/servers/erase-operations/${requestId}`);
    expect(calls).toHaveBeenCalledTimes(2);
});
