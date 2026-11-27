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
import { MemoryRouter } from "react-router-dom";

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
        .mockResolvedValue({
            profile,
            credentials_configured: true,
            vault_configured: true,
            editable: true,
            runs: [],
        });
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
                    version: 1,
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

it("requires a personal vault before showing credential inputs", async () => {
    vi.spyOn(client, "api").mockResolvedValue({
        profile: null,
        credentials_configured: false,
        vault_configured: false,
        editable: true,
        runs: [],
    });
    render(
        <MemoryRouter>
            <AnsibleSettings server="server-id" />
        </MemoryRouter>,
    );
    expect(
        await screen.findByRole("link", { name: "Mein Ansible-Vault" }),
    ).toHaveAttribute("href", "/settings/ansible-vault");
    expect(
        screen.queryByLabelText("Privater SSH-Schlüssel"),
    ).not.toBeInTheDocument();
    expect(
        screen.queryByRole("button", { name: "Verbindung speichern" }),
    ).not.toBeInTheDocument();
});

it("does not offer editing another user's vault credentials", async () => {
    vi.spyOn(client, "api").mockResolvedValue({
        profile,
        credentials_configured: true,
        vault_configured: true,
        editable: false,
        runs: [],
    });
    render(<AnsibleSettings server="server-id" />);
    expect(await screen.findByText(/Nur der Eigentümer/)).toBeVisible();
    expect(screen.queryByLabelText("SSH-Passwort")).not.toBeInTheDocument();
});
