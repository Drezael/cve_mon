function checkAborted(signal?: AbortSignal) {
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
}
import { clearMessageCache, t } from "./i18n/core";
import { z } from "zod";
export class ApiError extends Error {
    constructor(
        public status: number,
        public requestId?: string,
        public fields: string[] = [],
    ) {
        super(
            status === 0
                ? t("Die Verbindung ist unterbrochen. Bitte erneut versuchen.")
                : ({
                      401: t("Ihre Sitzung ist abgelaufen."),
                      403: t("Für diese Ansicht fehlt die Berechtigung."),
                      404: t("Der Eintrag ist nicht verfügbar."),
                      400: t("Die Eingaben konnten nicht übernommen werden."),
                      413: t("Die Anfrage ist zu groß."),
                      415: t("Dieses Dateiformat wird nicht unterstützt."),
                      422: t("Bitte prüfen Sie die Eingaben."),
                      412: t(
                          "Versionskonflikt: Der Stand wurde inzwischen geändert.",
                      ),
                      428: t(
                          "Der aktuelle Versionsstand fehlt. Bitte neu laden.",
                      ),
                      409: t("Der Zustand hat sich geändert."),
                      429: t("Zu viele Anfragen. Bitte kurz warten."),
                      504: t(
                          "Die Anfrage hat zu lange gedauert. Bitte erneut versuchen.",
                      ),
                      503: t("Der Dienst ist vorübergehend nicht erreichbar."),
                  }[status] ?? t("Die Daten konnten nicht geladen werden.")),
        );
    }
}
let csrf: string | null = null;
let generation = 0;
const active = new Set<AbortController>();
export function clearPrivate() {
    clearMessageCache();
    generation++;
    csrf = null;
    for (const c of active) c.abort();
    active.clear();
}
export async function api<T>(
    path: string,
    schema: z.ZodType<T>,
    options: {
        method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
        version?: number;
        idempotencyKey?: string;
        body?: unknown;
        signal?: AbortSignal;
        timeoutMs?: number;
    } = {},
): Promise<T> {
    if (!path.startsWith("/api/v1/") || path.includes("://"))
        throw new ApiError(400);
    const c = new AbortController();
    const epoch = generation;
    active.add(c);
    const abort = () => c.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) c.abort();
    const timeout = setTimeout(
        abort,
        Math.min(options.timeoutMs ?? 8000, 60000),
    );
    try {
        checkAborted(c.signal);
        const headers: Record<string, string> = { Accept: "application/json" };
        if (options.method && options.method !== "GET") {
            if (!csrf) await getCsrf(c.signal);
            checkAborted(c.signal);
            headers["X-CSRF-Token"] = csrf ?? "";
            if (!(options.body instanceof FormData))
                headers["Content-Type"] = "application/json";
            if (options.version !== undefined)
                headers["If-Match"] = `"${options.version}"`;
            if (options.idempotencyKey)
                headers["Idempotency-Key"] = options.idempotencyKey;
        }
        const response = await fetch(path, {
            method: options.method ?? "GET",
            credentials: "same-origin",
            cache: "no-store",
            redirect: "error",
            headers,
            body:
                options.body === undefined
                    ? undefined
                    : options.body instanceof FormData
                      ? options.body
                      : JSON.stringify(options.body),
            signal: c.signal,
        });
        if (!response.ok) {
            const challenge =
                options.method === "POST" &&
                /^\/api\/v1\/auth\/(login|reauthenticate|password\/change|activation\/redeem|mfa\/(verify|recovery|enroll\/confirm))$/.test(
                    path,
                );
            if (response.status === 401 && !challenge) {
                clearPrivate();
                window.dispatchEvent(new Event("session-expired"));
            }
            let fields: string[] = [];
            if (response.status === 422) {
                try {
                    const detail = await response.json();
                    const issues = detail.detail ?? detail.errors ?? [];
                    if (Array.isArray(issues))
                        fields = issues.flatMap((i: { loc?: unknown[]; pointer?: string }) =>
                            Array.isArray(i.loc)
                                ? [
                                      i.loc
                                          .filter(
                                              (v) =>
                                                  typeof v === "string" &&
                                                  v !== "body",
                                          )
                                          .join("."),
                                  ]
                                : typeof i.pointer === "string"
                                  ? [i.pointer.replace(/^\/(body\/)?/, "").replaceAll("/", ".")]
                                  : [],
                        );
                } catch {
                    /* bounded public validation only */
                }
            }
            throw new ApiError(
                response.status,
                response.headers.get("x-request-id") ?? undefined,
                fields,
            );
        }
        if (options.method && options.method !== "GET") csrf = null;
        const data = response.status === 204 ? null : await response.json();
        if (epoch !== generation)
            throw new DOMException("Superseded", "AbortError");
        const validated = schema.safeParse(data);
        if (!validated.success) throw new ApiError(502);
        return validated.data;
    } catch (error) {
        if (
            error instanceof DOMException &&
            error.name === "AbortError" &&
            !options.signal?.aborted &&
            epoch === generation
        )
            throw new ApiError(504);
        if (
            error instanceof ApiError ||
            (error instanceof DOMException && error.name === "AbortError")
        )
            throw error;
        throw new ApiError(0);
    } finally {
        // A failed/aborted mutation can still have consumed a preauth context.
        // Never retry the mutation; renew its context for the next user action.
        if (options.method && options.method !== "GET") csrf = null;
        clearTimeout(timeout);
        active.delete(c);
        options.signal?.removeEventListener("abort", abort);
    }
}
let csrfFlight: {
    epoch: number;
    controller: AbortController;
    promise: Promise<string>;
    waiters: number;
} | null = null;

export async function getCsrf(signal?: AbortSignal): Promise<string> {
    checkAborted(signal);
    if (csrf) return csrf;
    if (!csrfFlight || csrfFlight.epoch !== generation) {
        const epoch = generation;
        const controller = new AbortController();
        const flight = {
            epoch,
            controller,
            waiters: 0,
            promise: Promise.resolve(""),
        };
        flight.promise = api(
            "/api/v1/auth/csrf",
            z.object({ csrf_token: z.string() }),
            { signal: controller.signal },
        )
            .then((data) => {
                checkAborted(controller.signal);
                if (epoch !== generation)
                    throw new DOMException("Superseded", "AbortError");
                csrf = data.csrf_token;
                return csrf;
            })
            .finally(() => {
                if (csrfFlight === flight) csrfFlight = null;
            });
        csrfFlight = flight;
    }
    const flight = csrfFlight;
    flight.waiters++;
    let abort: (() => void) | undefined;
    try {
        return await Promise.race([
            flight.promise,
            new Promise<never>((_, reject) => {
                abort = () => reject(new DOMException("Aborted", "AbortError"));
                signal?.addEventListener("abort", abort, { once: true });
                if (signal?.aborted) abort();
            }),
        ]);
    } finally {
        if (abort) signal?.removeEventListener("abort", abort);
        if (--flight.waiters === 0 && csrfFlight === flight) {
            csrfFlight = null;
            flight.controller.abort();
        }
    }
}
export const authResult = z
    .object({
        state: z.string().optional(),
        provisioning_uri: z.string().optional(),
        recovery_codes: z.array(z.string()).optional(),
    })
    .passthrough();
