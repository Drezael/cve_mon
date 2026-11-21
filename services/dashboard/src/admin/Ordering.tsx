import { translateMessage, t, useLocale } from "../i18n";
import { useState } from "react";
import { useData, State, Card } from "../ui";
import { order, listing, type Row, text } from "./contracts";
import { DraftGuard, EditForm, Modal, type Mutation } from "./Form";
export default function Ordering() {
    useLocale();
    const path = "/api/v1/dashboard/admin/servers/order";
    const result = useData(path, order);
    const labels = useData("/api/v1/dashboard/servers?limit=100", listing);
    const [draft, setDraft] = useState<Row[] | null>(null);
    const [operation, setOperation] = useState<Mutation | null>(null);
    const [notice, setNotice] = useState("");
    const [discard, setDiscard] = useState(false);
    const items = draft ?? result.data?.items ?? [];
    function move(index: number, target: number) {
        const copy = [...items];
        const [item] = copy.splice(index, 1);
        copy.splice(Math.min(copy.length, Math.max(0, target)), 0, item);
        setDraft(copy);
    }
    return (
        <>
            <h1>{t("Manuelle Reihenfolge")}</h1>
            {!operation && (
                <DraftGuard
                    dirty={draft !== null}
                    onDiscard={() => setDraft(null)}
                />
            )}
            {draft && !operation && (
                <button onClick={() => setDiscard(true)}>
                    {t("Ungespeicherte Reihenfolge verwerfen")}
                </button>
            )}
            {discard && (
                <Modal
                    title={t("Ungespeicherte Reihenfolge")}
                    onCancel={() => setDiscard(false)}
                >
                    <p>
                        {t(
                            "Die lokale Reihenfolge wurde noch nicht gespeichert.",
                        )}
                    </p>
                    <button onClick={() => setDiscard(false)}>
                        {t("Weiter bearbeiten")}
                    </button>
                    <button
                        onClick={() => {
                            setDraft(null);
                            setDiscard(false);
                        }}
                    >
                        {t("Änderungen verwerfen")}
                    </button>
                </Modal>
            )}
            {notice && <p role="status">{translateMessage(notice)}</p>}
            {!result.data ? (
                <State error={result.error} reload={result.reload} />
            ) : (
                <Card title={t("Reihenfolge bearbeiten")}>
                    {result.data.total > 100 && (
                        <>
                            <p>
                                {t(
                                    "Mehr als 100 Einträge: Es werden ausschließlich relative Verschiebungen gespeichert, damit keine abgeschnittene Liste den Gesamtbestand überschreibt.",
                                )}
                            </p>
                            <button
                                onClick={() =>
                                    setOperation({
                                        title: t("Relative Reihenfolge ändern"),
                                        path,
                                        method: "PUT",
                                        version: result.data!.version,
                                        fields: [
                                            {
                                                key: "move_id",
                                                label: t(
                                                    "Zu verschiebender Eintrag",
                                                ),
                                                type: "picker",
                                                source: "/api/v1/dashboard/servers",
                                            },
                                            {
                                                key: "before_id",
                                                label: t(
                                                    "Einfügen vor (keine Auswahl: Ende)",
                                                ),
                                                type: "picker",
                                                source: "/api/v1/dashboard/servers",
                                            },
                                        ],
                                        initial: { before_id: null },
                                        validate: (v) =>
                                            !v.move_id ||
                                            v.move_id === v.before_id
                                                ? t(
                                                      "Einen Eintrag und gegebenenfalls einen anderen Zieleintrag auswählen.",
                                                  )
                                                : null,
                                    })
                                }
                            >
                                {t("Relative Verschiebung vorbereiten")}
                            </button>
                        </>
                    )}
                    <ol className="reorder">
                        {items.map((r, index) => (
                            <li key={text(r, "id")}>
                                <span>
                                    {text(
                                        labels.data?.items.find(
                                            (v) => v.id === r.id,
                                        ) ?? r,
                                        "display_name",
                                    ) ||
                                        text(
                                            labels.data?.items.find(
                                                (v) => v.id === r.id,
                                            ) ?? r,
                                            "name",
                                        ) ||
                                        text(r, "id")}
                                </span>
                                <div className="actions">
                                    <button
                                        disabled={
                                            index === 0 ||
                                            result.data!.total > 100
                                        }
                                        aria-label={t("{0}: An den Anfang", [
                                            index + 1,
                                        ])}
                                        onClick={() => move(index, 0)}
                                    >
                                        {t("Anfang")}
                                    </button>
                                    <button
                                        disabled={
                                            index === 0 ||
                                            result.data!.total > 100
                                        }
                                        aria-label={t("{0}: Nach oben", [
                                            index + 1,
                                        ])}
                                        onClick={() => move(index, index - 1)}
                                    >
                                        {t("Nach oben")}
                                    </button>
                                    <button
                                        disabled={
                                            index === items.length - 1 ||
                                            result.data!.total > 100
                                        }
                                        aria-label={t("{0}: Nach unten", [
                                            index + 1,
                                        ])}
                                        onClick={() => move(index, index + 1)}
                                    >
                                        {t("Nach unten")}
                                    </button>
                                    <button
                                        disabled={
                                            index === items.length - 1 ||
                                            result.data!.total > 100
                                        }
                                        aria-label={t("{0}: An das Ende", [
                                            index + 1,
                                        ])}
                                        onClick={() =>
                                            move(index, items.length - 1)
                                        }
                                    >
                                        {t("Ende")}
                                    </button>
                                </div>
                            </li>
                        ))}
                    </ol>
                    {draft && (
                        <button
                            onClick={() =>
                                setOperation({
                                    title: t("Reihenfolge speichern"),
                                    path,
                                    method: "PUT",
                                    version: result.data!.version,
                                    fields: [],
                                    initial: {},
                                    payload: () => ({
                                        ids: items.map((r) => r.id),
                                    }),
                                })
                            }
                        >
                            {t("Reihenfolge prüfen und speichern")}
                        </button>
                    )}
                </Card>
            )}
            {operation && (
                <EditForm
                    operation={{ ...operation, dirty: true }}
                    onCancel={() => {
                        setOperation(null);
                        setDraft(null);
                    }}
                    onReload={() => {
                        setOperation(null);
                        setDraft(null);
                        result.reload();
                    }}
                    onDone={() => {
                        setOperation(null);
                        setDraft(null);
                        setNotice(t("Gespeicherte Reihenfolge bestätigt."));
                        result.reload();
                    }}
                />
            )}
        </>
    );
}
