import { localized } from "./../i18n";
import { options, type Field } from "./Form";
export const serverFields: Field[] = localized([
    {
        key: "display_name",
        label: "Serverbezeichnung",
        required: true,
        max: 128,
    },
    { key: "description", label: "Beschreibung", type: "textarea", max: 2000 },
    { key: "environment", label: "Umgebung", max: 64 },
    {
        key: "criticality",
        label: "Kritikalität",
        type: "select",
        required: true,
        options: options(["low", "medium", "high", "critical"]),
    },
    {
        key: "exposure",
        label: "Erreichbarkeit",
        type: "select",
        required: true,
        options: options([
            "unknown",
            "internal",
            "restricted",
            "internet_exposed",
        ]),
    },
]);
