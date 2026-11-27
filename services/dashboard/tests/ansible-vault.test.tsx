import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import * as client from "../src/api";
import AnsibleVault from "../src/admin/AnsibleVault";

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

it("requires account reauthentication and clears the vault password after saving", async () => {
    let configured = false;
    const calls = vi
        .spyOn(client, "api")
        .mockImplementation(async (path, _schema, options) => {
            if (path === "/api/v1/auth/reauthenticate")
                return { state: "authenticated" };
            if (options?.method === "PUT") configured = true;
            return { configured };
        });
    render(
        <RouterProvider
            router={createMemoryRouter([
                { path: "/", element: <AnsibleVault /> },
            ])}
        />,
    );
    fireEvent.click(
        await screen.findByRole("button", { name: "Vault einrichten" }),
    );
    const secret = "fixture-vault-password-only"; // pragma: allowlist secret -- synthetic fixture
    fireEvent.change(screen.getByLabelText("Neues Vault-Passwort"), {
        target: { value: secret },
    });
    fireEvent.change(screen.getByLabelText("Vault-Passwort wiederholen"), {
        target: { value: secret },
    });
    fireEvent.click(screen.getByRole("button", { name: "Speichern" }));
    expect(
        calls.mock.calls.some(([, , options]) => options?.method === "PUT"),
    ).toBe(false);
    fireEvent.change(await screen.findByLabelText("Aktuelles Passwort"), {
        target: { value: "fixture-account-password" },
    });
    fireEvent.click(
        screen.getByRole("button", {
            name: "Identität bestätigen und speichern",
        }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
        "Vault gespeichert.",
    );
    await waitFor(() =>
        expect(calls).toHaveBeenCalledWith(
            "/api/v1/dashboard/me/ansible-vault",
            expect.anything(),
            expect.objectContaining({
                method: "PUT",
                body: { password: secret, password_confirmation: secret },
            }),
        ),
    );
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
    expect(
        screen.queryByLabelText("Neues Vault-Passwort"),
    ).not.toBeInTheDocument();
    expect(
        screen.getByRole("button", { name: "Vault-Passwort ändern" }),
    ).toBeVisible();
    expect(localStorage.getItem("vault-password")).toBeNull();
});
