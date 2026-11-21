import { useSyncExternalStore } from "react";
import { getLocale, subscribe, type Locale } from "./core";
export {
    t,
    localized,
    intlLocale,
    getLocale,
    setLocale,
    plural,
    translateMessage,
} from "./core";
export type { Locale } from "./core";
export function useLocale() {
    return useSyncExternalStore(subscribe, getLocale, () => "en" as Locale);
}
