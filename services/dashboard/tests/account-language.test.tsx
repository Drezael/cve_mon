import { afterEach, describe, expect, it, vi } from "vitest";
import {
    act,
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import * as client from "../src/api";
import { getLocale, setLocale } from "../src/i18n";
import {
    LanguageSettings,
    InstanceLanguageSettings,
} from "../src/settings/Language";
import {
    PERSONAL_LOCALE,
    INSTANCE_LOCALE,
    synchronizeLocale,
} from "../src/settings/localization";

const inherited = {
    locale: null,
    effective_locale: "en",
    default_locale: "en",
    version: 0,
};
afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    setLocale("de");
});
describe("Persistent account language", () => {
    it("waits for the account save before switching and never writes local storage", async () => {
        const storage = vi.spyOn(Storage.prototype, "setItem");
        let complete: ((value: unknown) => void) | undefined;
        const calls = vi
            .spyOn(client, "api")
            .mockImplementation(async (path, _schema, options) => {
                if (path === PERSONAL_LOCALE && options?.method === "PUT")
                    return new Promise((resolve) => {
                        complete = resolve;
                    });
                return inherited;
            });
        render(<LanguageSettings />);
        const select = await screen.findByLabelText("Sprache", {
            selector: "select",
        });
        fireEvent.change(select, { target: { value: "en" } });
        expect(getLocale()).toBe("de");
        expect(select).toBeDisabled();
        expect(calls).toHaveBeenLastCalledWith(
            PERSONAL_LOCALE,
            expect.anything(),
            { method: "PUT", version: 0, body: { locale: "en" } },
        );
        await act(async () =>
            complete?.({ ...inherited, locale: "en", version: 1 }),
        );
        expect(getLocale()).toBe("en");
        expect(screen.getByLabelText("Language", { selector: "select" })).toBe(
            select,
        );
        expect(
            screen.getByText("Language saved to your account."),
        ).toBeVisible();
        expect(storage).not.toHaveBeenCalled();
    });
    it("retains the confirmed language on save failure and reloads the saved value", async () => {
        const calls = vi
            .spyOn(client, "api")
            .mockImplementation(async (_path, _schema, options) => {
                if (options?.method === "PUT") throw new client.ApiError(503);
                return {
                    ...inherited,
                    locale: "de",
                    effective_locale: "de",
                    version: 4,
                };
            });
        const view = render(<LanguageSettings />);
        fireEvent.change(
            await screen.findByLabelText("Sprache", { selector: "select" }),
            { target: { value: "en" } },
        );
        await screen.findByRole("alert");
        expect(getLocale()).toBe("de");
        expect(
            screen.getByLabelText("Sprache", { selector: "select" }),
        ).toHaveValue("de");
        view.unmount();
        render(<LanguageSettings />);
        await waitFor(() =>
            expect(
                screen.getByLabelText("Sprache", { selector: "select" }),
            ).toHaveValue("de"),
        );
        expect(calls).toHaveBeenCalledTimes(3);
    });
    it("uses the instance default when the personal override is removed", async () => {
        vi.spyOn(client, "api").mockImplementation(
            async (_path, _schema, options) =>
                options?.method === "PUT"
                    ? inherited
                    : {
                          ...inherited,
                          locale: "de",
                          effective_locale: "de",
                          version: 2,
                      },
        );
        render(<LanguageSettings />);
        fireEvent.change(
            await screen.findByLabelText("Sprache", { selector: "select" }),
            { target: { value: "" } },
        );
        await screen.findByText("Language saved to your account.");
        expect(getLocale()).toBe("en");
    });
    it("does not let an older refresh overwrite a newly saved language", async () => {
        let complete: ((value: unknown) => void) | undefined;
        vi.spyOn(client, "api").mockImplementation(
            async () =>
                new Promise((resolve) => {
                    complete = resolve;
                }),
        );
        const pending = synchronizeLocale(true);
        setLocale("en");
        complete?.({ ...inherited, locale: "de", effective_locale: "de" });
        await pending;
        expect(getLocale()).toBe("en");
    });
    it("reads the public default for sign-in and the personal preference after authentication", async () => {
        const calls = vi
            .spyOn(client, "api")
            .mockImplementation(async (path) =>
                path === PERSONAL_LOCALE
                    ? { ...inherited, locale: "de", effective_locale: "de" }
                    : { default_locale: "en" },
            );
        await synchronizeLocale(false);
        expect(getLocale()).toBe("en");
        await synchronizeLocale(true);
        expect(getLocale()).toBe("de");
        expect(calls.mock.calls.map(([p]) => p)).toEqual([
            "/api/v1/dashboard/localization",
            PERSONAL_LOCALE,
        ]);
    });
});
it("saves the versioned instance language separately from account settings", async () => {
    const calls = vi
        .spyOn(client, "api")
        .mockImplementation(async (_path, _schema, options) => ({
            default_locale: options?.method === "PUT" ? "de" : "en",
            version: options?.method === "PUT" ? 4 : 3,
            updated_at: null,
        }));
    render(<InstanceLanguageSettings />);
    fireEvent.change(
        await screen.findByLabelText("Standardsprache", { selector: "select" }),
        { target: { value: "de" } },
    );
    fireEvent.click(
        screen.getByRole("button", { name: "Standardsprache speichern" }),
    );
    await screen.findByText("Standardsprache gespeichert.");
    expect(
        calls.mock.calls.some(
            ([p, , o]) =>
                p === INSTANCE_LOCALE &&
                o?.method === "PUT" &&
                o.version === 3 &&
                JSON.stringify(o.body) === '{"default_locale":"de"}',
        ),
    ).toBe(true);
    expect(calls.mock.calls.every(([p]) => p === INSTANCE_LOCALE)).toBe(true);
    await waitFor(() =>
        expect(
            screen.getByRole("button", { name: "Standardsprache speichern" }),
        ).not.toBeDisabled(),
    );
});
