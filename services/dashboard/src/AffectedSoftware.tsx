import { t, useLocale } from "./i18n";
import type { z } from "zod";
import type { affectedSoftwareSchema } from "./contracts";
import { label } from "./format";

type Software = z.infer<typeof affectedSoftwareSchema>;
export default function AffectedSoftware({
    items = [],
    compact = false,
}: {
    items?: Software[];
    compact?: boolean;
}) {
    useLocale();
    if (!items.length) return <p>{t("Software nicht eindeutig ermittelt.")}</p>;
    return (
        <ul className="affected-software">
            {items.map((item, index) => (
                <li key={`${item.component_id}:${index}`}>
                    <strong>
                        {item.name ?? t("Software nicht eindeutig ermittelt")}
                    </strong>{" "}
                    {item.version ?? t("Version unbekannt")}
                    <div
                        className={`software-location software-location-${item.location}`}
                    >
                        {item.location === "container"
                            ? t("Container: {0}", [
                                  item.container_name ??
                                      item.container_id ??
                                      t("Name unbekannt"),
                              ])
                            : item.location === "host"
                              ? t("Host")
                              : t("Bereich nicht eindeutig ermittelt")}
                    </div>
                    <small>{label(item.status)}</small>
                    {!compact && (
                        <>
                            {item.origin && (
                                <small>
                                    {" "}
                                    ·{" "}
                                    {(
                                        {
                                            image: t("Image"),
                                            runtime: t("Laufzeit"),
                                            mount: t("Eingebundene Anwendung"),
                                        } as Record<string, string>
                                    )[item.origin] ?? item.origin}
                                    {item.target ? ` (${item.target})` : ""}
                                </small>
                            )}
                        </>
                    )}
                </li>
            ))}
        </ul>
    );
}
