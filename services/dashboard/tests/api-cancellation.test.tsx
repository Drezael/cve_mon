import { afterEach, expect, it, vi } from "vitest";
import { z } from "zod";
import { api, clearPrivate } from "../src/api";

afterEach(() => {
    clearPrivate();
    vi.unstubAllGlobals();
});

it("never fetches with an already aborted signal", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const c = new AbortController();
    c.abort();
    await expect(
        api("/api/v1/dashboard/test", z.unknown(), { signal: c.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(fetch).not.toHaveBeenCalled();
});

it("shares token retrieval while one caller cancels independently", async () => {
    let resolve!: (value: Response) => void;
    const fetch = vi.fn((path: string) =>
        path.endsWith("/csrf")
            ? new Promise<Response>((done) => {
                  resolve = done;
              })
            : Promise.resolve(new Response('{"ok":true}')),
    );
    vi.stubGlobal("fetch", fetch);
    const c = new AbortController();
    const first = api("/api/v1/dashboard/a", z.object({ ok: z.boolean() }), {
        method: "PUT",
        signal: c.signal,
    });
    const rejected = expect(first).rejects.toMatchObject({
        name: "AbortError",
    });
    const second = api("/api/v1/dashboard/b", z.object({ ok: z.boolean() }), {
        method: "PUT",
    });
    c.abort();
    await rejected;
    resolve(new Response('{"csrf_token":"fixture"}'));
    await expect(second).resolves.toEqual({ ok: true });
    expect(fetch.mock.calls.map(([path]) => path)).toEqual([
        "/api/v1/auth/csrf",
        "/api/v1/dashboard/b",
    ]);
});

it("cannot resurrect a token or start a mutation after logout", async () => {
    let resolve!: (value: Response) => void;
    const fetch = vi.fn(
        () =>
            new Promise<Response>((done) => {
                resolve = done;
            }),
    );
    vi.stubGlobal("fetch", fetch);
    const pending = api("/api/v1/dashboard/a", z.unknown(), { method: "POST" });
    const rejected = expect(pending).rejects.toMatchObject({
        name: "AbortError",
    });
    clearPrivate();
    resolve(new Response('{"csrf_token":"old"}'));
    await rejected;
    expect(fetch).toHaveBeenCalledTimes(1);
});
