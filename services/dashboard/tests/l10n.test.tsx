import {
    act,
    cleanup,
    fireEvent,
    render,
    screen,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { useEffect, useState } from "react";
import {
    getLocale,
    localized,
    setLocale,
    t,
    useLocale,
    translateMessage,
} from "../src/i18n";
import { LEGACY_STORAGE_KEY } from "../src/i18n/core";
import { clearPrivate } from "../src/api";
import german from "../src/i18n/de.json";
import english from "../src/i18n/en.json";
import { date, number, percent } from "../src/format";
import { Badge, Facts } from "../src/ui";
import Login from "../src/pages/Login";
import Threat from "../src/Threat";

afterEach(() => {
    cleanup();
    setLocale("de");
    localStorage.clear();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});

// Test harness for the reactive localization core; the production selector lives in account settings.
function LanguageSwitcher() {
    const locale = useLocale();
    return (
        <select
            aria-label={t("Sprache")}
            value={locale}
            onChange={(e) => setLocale(e.target.value as "de" | "en")}
        >
            <option value="de">Deutsch</option>
            <option value="en">English</option>
        </select>
    );
}

const fields = localized({
    label: "Benutzername",
    key: "username",
    options: [{ name: "Montag", id: "0" }],
});
function Draft({ mounted }: { mounted: () => void }) {
    useLocale();
    const [value, setValue] = useState("");
    useEffect(mounted, [mounted]);
    return (
        <>
            <LanguageSwitcher />
            <label>
                {fields.label}
                <input
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                />
            </label>
            <p>{fields.options[0].name}</p>
            <p>{number(1234.5)}</p>
            <p>{percent(0.125)}</p>
            <p>{date("2026-11-18T09:00:00Z")}</p>
            <Badge value="potentially_affected" />
            <Threat
                finding={{
                    current_priority: "high",
                    cvss: { base_score: 7.5 },
                }}
            />
            <Facts
                values={{
                    description: "Benachrichtigungen",
                    actor_user_id: "Benutzer",
                }}
            />
        </>
    );
}

describe("Live localization", () => {
    it("switches the complete view without remounting, networking or losing a draft", () => {
        const mounted = vi.fn();
        const fetch = vi.fn();
        vi.stubGlobal("fetch", fetch);
        render(<Draft mounted={mounted} />);
        const input = screen.getByLabelText("Benutzername");
        fireEvent.change(input, { target: { value: "my-server" } });
        fireEvent.change(screen.getByLabelText("Sprache"), {
            target: { value: "en" },
        });
        expect(screen.getByLabelText("Username")).toBe(input);
        expect(input).toHaveValue("my-server");
        expect(mounted).toHaveBeenCalledTimes(1);
        expect(fetch).not.toHaveBeenCalled();
        expect(screen.getByText("Monday")).toBeVisible();
        expect(screen.getByText("1,234.5")).toBeVisible();
        expect(screen.getByText("12.5%")).toBeVisible();
        expect(screen.getByText("Affected")).toBeVisible();
        expect(screen.getByText("High")).toBeVisible();
        // Values supplied by users or the inventory must remain unchanged.
        expect(screen.getByText("Benachrichtigungen")).toBeVisible();
        expect(screen.getByText("Benutzer")).toBeVisible();
        expect(fields.key).toBe("username");
        expect(fields.options[0].id).toBe("0");
        expect(document.documentElement.lang).toBe("en");
        expect(localStorage.getItem(LEGACY_STORAGE_KEY)).toBeNull();
        fireEvent.change(screen.getByLabelText("Language"), {
            target: { value: "de" },
        });
        expect(screen.getByLabelText("Benutzername")).toBe(input);
        expect(screen.getByText("Montag")).toBeVisible();
        expect(screen.getByText("Betroffen")).toBeVisible();
        expect(document.documentElement.lang).toBe("de");
        vi.unstubAllGlobals();
    });
    it("preserves login fields and updates accessible labels immediately", () => {
        render(
            <MemoryRouter>
                <Login />
            </MemoryRouter>,
        );
        fireEvent.change(
            screen.getByLabelText("Benutzername", { exact: true }),
            { target: { value: "test-user" } },
        );
        act(() => setLocale("en"));
        expect(
            screen.getByRole("heading", { name: "Welcome back" }),
        ).toBeVisible();
        expect(screen.getByLabelText("Username", { exact: true })).toHaveValue(
            "test-user",
        );
        expect(
            screen.getByLabelText("Password", { exact: true }),
        ).toBeVisible();
    });
    it("ignores legacy browser storage and can switch while storage is blocked", () => {
        render(<LanguageSwitcher />);
        act(() =>
            window.dispatchEvent(
                new StorageEvent("storage", {
                    key: LEGACY_STORAGE_KEY,
                    newValue: "en",
                }),
            ),
        );
        expect(screen.getByLabelText("Sprache")).toHaveValue("de");
        vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
            throw new Error("Storage blocked");
        });
        act(() => setLocale("en"));
        expect(getLocale()).toBe("en");
        expect(screen.getByLabelText("Language")).toHaveValue("en");
    });
    it("updates existing notices and escapes interpolation as plain React text", () => {
        setLocale("en");
        const message = t("Speichern fehlgeschlagen.");
        setLocale("de");
        expect(translateMessage(message)).toBe("Speichern fehlgeschlagen.");
        setLocale("en");
        render(
            <p>{t("Server {0} löschen", ["<img src=x onerror=alert(1)>"])}</p>,
        );
        expect(
            screen.getByText("Delete server <img src=x onerror=alert(1)>"),
        ).toBeVisible();
        expect(document.querySelector("img")).toBeNull();
    });
});

describe("Translation catalog contract", () => {
    it("keeps unknown technical keys and prototype names as plain text", () => {
        setLocale("en");
        for (const value of [
            "__proto__",
            "constructor",
            "toString",
            "CVE-2026-12345",
        ])
            expect(t(value)).toBe(value);
    });
    it("provides both languages with matching parameter placeholders", () => {
        expect(Object.keys(english).sort()).toEqual(Object.keys(german).sort());
        expect(Object.keys(english).length).toBeGreaterThan(1000);
        for (const [key, value] of Object.entries(english)) {
            expect(value.trim().length, key).toBeGreaterThan(0);
            expect(value.match(/\{\d+\}/g)?.sort() ?? [], key).toEqual(
                key.match(/\{\d+\}/g)?.sort() ?? [],
            );
        }
    });
});

it("includes every literal translation call in both catalogs", () => {
    const sources = import.meta.glob<string>("../src/**/*.{ts,tsx}", {
        query: "?raw",
        import: "default",
        eager: true,
    });
    for (const [file, source] of Object.entries(sources)) {
        if (file.includes("/generated/")) continue;
        for (const match of source.matchAll(/\bt\(("(?:[^"\\]|\\.)*")/g)) {
            const key = JSON.parse(match[1]) as string;
            expect(Object.hasOwn(german, key), file + ": " + key).toBe(true);
            expect(Object.hasOwn(english, key), file + ": " + key).toBe(true);
        }
    }
});

it("drops interpolated private messages when the authorization context is cleared", () => {
    setLocale("en");
    const rendered = t("Server {0} löschen", ["private-demo-name"]);
    setLocale("de");
    expect(translateMessage(rendered)).toBe("Server private-demo-name löschen");
    clearPrivate();
    expect(translateMessage(rendered)).toBe(rendered);
    expect(localStorage.getItem(LEGACY_STORAGE_KEY)).toBeNull();
});
