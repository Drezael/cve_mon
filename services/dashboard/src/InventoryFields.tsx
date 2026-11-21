import { t, localized, useLocale } from "./i18n";
import { useState } from "react";
import type { Row } from "./admin/contracts";
import { Inputs, type Field } from "./admin/Form";
const hardwareFields: Field[] = localized([
    { key: "cpu_count", label: "CPU-Anzahl", type: "number", min: 1 },
    {
        key: "memory_mb",
        label: "Arbeitsspeicher (MiB)",
        type: "number",
        min: 1,
    },
    { key: "virtualization_type", label: "Virtualisierungstyp", max: 128 },
    { key: "virtualization_role", label: "Virtualisierungsrolle", max: 64 },
]);
const titles: Record<string, string> = localized({
    host: "Servererkennung",
    os: "Betriebssystem",
    packages: "Installierte Software",
    containers: "Container",
    images: "Container-Images",
    services: "Dienste",
    hardware: "Hardware",
    container_software: "Software in Containern",
    software_bills: "Software-Stücklisten",
});
export default function InventoryFields({
    value,
    onChange,
}: {
    value: Row;
    onChange: (next: Row) => void;
}) {
    useLocale();
    function update(path: (string | number)[], next: unknown) {
        const copy = structuredClone(value);
        let target: unknown = copy;
        for (const part of path.slice(0, -1))
            target = (target as Record<string | number, unknown>)[part];
        (target as Record<string | number, unknown>)[path[path.length - 1]] =
            next;
        onChange(copy);
    }
    return (
        <section aria-label={t("Inventardaten")}>
            <h2>{t("Inventardaten")}</h2>
            <p>
                {t(
                    "Serverkennung, Betriebssystem, Software und Versionsangaben sind geschützt. Hardwareangaben und die beschreibenden Angaben zu Diensten können Sie bearbeiten.",
                )}
            </p>
            <details>
                <summary>{t("Hardware bearbeiten")}</summary>
                <Inputs
                    fields={hardwareFields}
                    values={(value.hardware as Row | undefined) ?? {}}
                    set={(key, item) => {
                        const hardware = {
                            ...((value.hardware as Row | undefined) ?? {}),
                        };
                        if (item === "" || item == null) delete hardware[key];
                        else
                            hardware[key] = ["cpu_count", "memory_mb"].includes(
                                key,
                            )
                                ? Number(item)
                                : item;
                        onChange({ ...value, hardware });
                    }}
                />
            </details>
            {Object.entries(value)
                .filter(([key]) => key !== "hardware")
                .map(([key, item]) => (
                    <InventoryGroup
                        key={key}
                        name={titles[key] ?? key}
                        value={item}
                        path={[key]}
                        onChange={update}
                    />
                ))}
        </section>
    );
}
function InventoryGroup({
    name,
    value,
    path,
    onChange,
}: {
    name: string;
    value: unknown;
    path: (string | number)[];
    onChange: (path: (string | number)[], value: unknown) => void;
}) {
    useLocale();
    const [open, setOpen] = useState(false);
    const [limit, setLimit] = useState(25);
    const editable = path[0] === "services" && path[1] === "items";
    if (value !== null && typeof value === "object") {
        const entries = Array.isArray(value)
            ? value.slice(0, limit).map((item, index) => [index, item] as const)
            : Object.entries(value);
        return (
            <details onToggle={(event) => setOpen(event.currentTarget.open)}>
                <summary>
                    {name}
                    {Array.isArray(value) ? ` (${value.length})` : ""}
                </summary>
                {open && (
                    <div className="inventory-fields">
                        {entries.map(([key, item]) => (
                            <InventoryGroup
                                key={key}
                                name={String(key)}
                                path={[...path, key]}
                                value={item}
                                onChange={onChange}
                            />
                        ))}
                        {Array.isArray(value) && value.length > limit && (
                            <button
                                type="button"
                                onClick={() =>
                                    setLimit((current) => current + 25)
                                }
                            >
                                {t("Weitere Einträge anzeigen")}
                            </button>
                        )}
                    </div>
                )}
            </details>
        );
    }
    const label = path.join(".");
    return (
        <label>
            {label}
            {typeof value === "boolean" ? (
                <input
                    type="checkbox"
                    aria-label={label}
                    checked={value}
                    disabled={!editable}
                    onChange={(event) => onChange(path, event.target.checked)}
                />
            ) : (
                <input
                    aria-label={label}
                    readOnly={!editable}
                    type={typeof value === "number" ? "number" : "text"}
                    value={value === null ? "" : String(value)}
                    onChange={(event) => {
                        if (editable)
                            onChange(
                                path,
                                typeof value === "number"
                                    ? Number(event.target.value)
                                    : event.target.value,
                            );
                    }}
                />
            )}
        </label>
    );
}
