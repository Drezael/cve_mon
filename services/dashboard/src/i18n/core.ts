import english from "./en.json";
import german from "./de.json";

export type Locale = "de" | "en";
export const LEGACY_STORAGE_KEY = "cve-monitor.locale";
const catalog: Readonly<Record<string, string>> = english;
const sourceCatalog: Readonly<Record<string, string>> = german;
const sourceMessages = new Map(
    Object.entries(catalog).map(([key, value]) => [value, key]),
);
const interpolatedMessages = new Map<
    string,
    { key: string; values: readonly unknown[] }
>();
const listeners = new Set<() => void>();

export function clearMessageCache() {
    interpolatedMessages.clear();
}

// Account and instance settings are authoritative; discard the previous browser-only choice.
try {
    localStorage.removeItem(LEGACY_STORAGE_KEY);
} catch {
    /* Storage may be blocked. */
}
let locale: Locale = "en";
let revision = 0;
export const getLocaleRevision = () => revision;
export const getLocale = () => locale;
export const intlLocale = () => (locale === "de" ? "de-DE" : "en-GB");
export function subscribe(listener: () => void) {
    listeners.add(listener);
    return () => {
        listeners.delete(listener);
    };
}
export function setLocale(value: Locale) {
    if (value !== "de" && value !== "en") return;
    revision++;
    applyLocale(value);
}
function applyLocale(value: Locale) {
    if (typeof document !== "undefined") document.documentElement.lang = value;
    if (locale === value) return;
    locale = value;
    for (const listener of listeners) listener();
}
if (typeof document !== "undefined") document.documentElement.lang = locale;
/** German source messages are stable keys. Parameters are text, never HTML. */
export function t(message: string, values: readonly unknown[] = []): string {
    const messages = locale === "en" ? catalog : sourceCatalog;
    const translated = Object.hasOwn(messages, message)
        ? messages[message]
        : message;
    const result = translated.replace(
        /\{(\d+)\}/g,
        (placeholder, position: string) =>
            Number(position) < values.length
                ? String(values[Number(position)] ?? "")
                : placeholder,
    );
    if (values.length && Object.hasOwn(sourceCatalog, message)) {
        if (interpolatedMessages.size >= 500) interpolatedMessages.clear();
        interpolatedMessages.set(result, { key: message, values });
    }
    return result;
}
/** Retranslate application notices already stored before a language change. */
export function translateMessage(message: string | null | undefined): string {
    const original = message ? interpolatedMessages.get(message) : undefined;
    if (original) return t(original.key, original.values);
    return message ? t(sourceMessages.get(message) ?? message) : "";
}
/** Static source configuration remains reactive without rebuilding schemas or form state. */
const proxies = new WeakMap<object, object>();
export function localized<T extends object>(source: T): T {
    const previous = proxies.get(source);
    if (previous) return previous as T;
    const proxy = new Proxy(source, {
        get(target, property, receiver) {
            const value: unknown = Reflect.get(target, property, receiver);
            if (typeof value === "string") return translateMessage(value);
            if (
                value &&
                typeof value === "object" &&
                (Array.isArray(value) ||
                    Object.getPrototypeOf(value) === Object.prototype)
            )
                return localized(value);
            return value;
        },
    });
    proxies.set(source, proxy);
    return proxy;
}
export const plural = (count: number, one: string, other: string) =>
    t(
        new Intl.PluralRules(intlLocale()).select(count) === "one"
            ? one
            : other,
        [new Intl.NumberFormat(intlLocale()).format(count)],
    );
