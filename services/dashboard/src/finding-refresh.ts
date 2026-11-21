import type { MouseEvent } from "react";
export const FINDINGS_REFRESH = "cve-findings-refresh";
export const FINDINGS_CHANGED = "cve-findings-changed";
export const FINDINGS_REFRESH_INTERVAL = 10000;

export function refreshFindingNavigation(
    event: MouseEvent<HTMLAnchorElement>,
    pathname: string,
): boolean {
    if (
        pathname.replace(/\/+$/, "") !== "/findings" ||
        event.defaultPrevented ||
        event.button !== 0 ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey
    )
        return false;
    event.preventDefault();
    window.dispatchEvent(new Event(FINDINGS_REFRESH));
    return true;
}
