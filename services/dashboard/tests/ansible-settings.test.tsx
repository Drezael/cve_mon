import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import * as client from "../src/api";
import AnsibleSettings from "../src/admin/AnsibleSettings";

const profile = {
    version: 1,
    host: "192.168.1.20",
    port: 22,
    username: "collector",
    auth_method: "password",
    use_sudo: false,
    enabled: false,
    interval_seconds: 3600,
    next_due: null,
    host_key: null,
    host_key_confirmed: false,
    mount_paths: [],
};
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});

it("requires a confirmed hostkey before login and retains write-only credentials", async () => {
    const calls = vi
        .spyOn(client, "api")
        .mockResolvedValue({ profile, credentials_configured: true, runs: [] });
    render(<AnsibleSettings server="server-id" />);
    await screen.findByDisplayValue("192.168.1.20");
    expect(
        screen.getByRole("button", { name: "Verbindung testen" }),
    ).toBeDisabled();
    expect(
        screen.getByRole("button", { name: "Jetzt erfassen" }),
    ).toBeDisabled();
    expect(screen.getByLabelText("SSH-Passwort")).toHaveValue("");
    fireEvent.change(screen.getByLabelText("Abfrageintervall in Minuten"), {
        target: { value: "30" },
    });
    fireEvent.click(
        screen.getByRole("button", { name: "Verbindung speichern" }),
    );
    await waitFor(() =>
        expect(calls).toHaveBeenCalledWith(
            "/api/v1/dashboard/servers/server-id/ansible",
            expect.anything(),
            {
                method: "PUT",
                body: {
                    host: profile.host,
                    port: 22,
                    username: "collector",
                    auth_method: "password",
                    use_sudo: false,
                    enabled: false,
                    interval_seconds: 1800,
                    mount_paths: [],
                },
            },
        ),
    );
    expect(
        calls.mock.calls.some(([, , options]) => options?.method === "POST"),
    ).toBe(false);
});
