import { afterEach, expect, it, vi } from "vitest";
import { z } from "zod";
import { api, clearPrivate } from "../src/api";

afterEach(() => { clearPrivate(); vi.unstubAllGlobals(); });

it.each(["invalid", "network"])("renews consumed login context after %s failure without retrying POST", async (kind) => {
    let issued = 0;
    let posts = 0;
    let consumed = false;
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
        if (path.endsWith("/csrf")) {
            issued++;
            consumed = false;
            return new Response(JSON.stringify({ csrf_token: `context-${issued}` }));
        }
        posts++;
        if (consumed) return new Response("{}", { status: 403 });
        consumed = true;
        if (posts === 1) {
            if (kind === "network") throw new TypeError("Connection lost");
            return new Response("{}", { status: 401 });
        }
        return new Response(JSON.stringify({ state: "authenticated" }));
    }));
    await expect(api("/api/v1/auth/login", z.unknown(), { method: "POST", body: {} })).rejects.toBeInstanceOf(Error);
    expect(posts).toBe(1);
    await expect(api("/api/v1/auth/login", z.unknown(), { method: "POST", body: {} })).resolves.toEqual({ state: "authenticated" });
    expect(posts).toBe(2);
    expect(issued).toBe(2);
});
