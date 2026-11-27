import { useState } from "react";
import { t, useLocale } from "../i18n";
import { useData, State, Facts, Pagination } from "../ui";
import { listing } from "./contracts";

export default function VersionHistory({
    kind,
    identity,
}: {
    kind: "rules" | "templates";
    identity: string;
}) {
    useLocale();
    const [offset, setOffset] = useState(0);
    const history = useData(
        `/api/v1/dashboard/administration/notification-history/${kind}/${identity}?limit=25&offset=${offset}`,
        listing,
    );
    const [chosen, setChosen] = useState("");
    return (
        <section>
            <h3>{t("Unveränderte Versionshistorie")}</h3>
            {!history.data ? (
                <State error={history.error} reload={history.reload} />
            ) : (
                <>
                    <label>
                        {t("Version zum Vergleich")}
                        <select
                            value={chosen}
                            onChange={(e) => setChosen(e.target.value)}
                        >
                            <option value="">{t("Version wählen")}</option>
                            {history.data.items.map((r) => (
                                <option key={String(r.id)} value={String(r.id)}>
                                    {t("Version")} {String(r.version)}
                                </option>
                            ))}
                        </select>
                    </label>
                    {chosen && (
                        <div className="grid-two">
                            <Facts values={history.data.items[0] ?? {}} />
                            <Facts
                                values={
                                    history.data.items.find(
                                        (r) => r.id === chosen,
                                    ) ?? {}
                                }
                            />
                        </div>
                    )}
                    {history.data.items.map((r) => (
                        <details key={String(r.id)}>
                            <summary>
                                {t("Version")} {String(r.version)} ·{" "}
                                {String(r.created_at ?? "")}
                            </summary>
                            <Facts values={r} />
                        </details>
                    ))}
                    <Pagination
                        offset={offset}
                        total={history.data.total}
                        onChange={setOffset}
                    />
                </>
            )}
        </section>
    );
}
