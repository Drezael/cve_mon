import { z } from "zod";
import { api } from "../api";
import { setLocale } from "../i18n";
import { getLocaleRevision } from "../i18n/core";

export const localeSchema = z.enum(["de", "en"]);
export const personalSchema = z.object({
    locale: localeSchema.nullable(),
    effective_locale: localeSchema,
    default_locale: localeSchema,
    version: z.number().int().nonnegative(),
});
export const instanceSchema = z.object({
    default_locale: localeSchema,
    version: z.number().int().nonnegative(),
    updated_at: z.string().nullable(),
});
export const PERSONAL_LOCALE = "/api/v1/dashboard/me/locale";
export const INSTANCE_LOCALE = "/api/v1/dashboard/administration/localization";
export const LOCALE_UPDATED = "cve-locale-updated";

export async function readLocale(authenticated: boolean) {
    return authenticated
        ? (await api(PERSONAL_LOCALE, personalSchema)).effective_locale
        : (
              await api(
                  "/api/v1/dashboard/localization",
                  z.object({ default_locale: localeSchema }),
              )
          ).default_locale;
}
export async function synchronizeLocale(authenticated: boolean) {
    const revision = getLocaleRevision();
    try {
        const language = await readLocale(authenticated);
        if (getLocaleRevision() === revision) setLocale(language);
    } catch {
        /* Keep rendering and authentication available during a temporary outage. */
    }
}
export function announceLocaleChange() {
    const channel = new BroadcastChannel("cve-locale");
    channel.postMessage("settings-changed");
    channel.close();
}
