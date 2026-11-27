import { t, useLocale } from "../i18n";

export default function SafePreview({ html }: { html: string }) {
    useLocale();
    const document = new DOMParser().parseFromString(html, "text/html");
    const nodes = (items: NodeListOf<ChildNode>): import("react").ReactNode =>
        Array.from(items).map((node, index) => {
            if (node.nodeType === 3) return node.textContent;
            if (!(node instanceof Element)) return null;
            const children = nodes(node.childNodes);
            switch (node.tagName.toLowerCase()) {
                case "p":
                    return <p key={index}>{children}</p>;
                case "h2":
                    return <h3 key={index}>{children}</h3>;
                case "ul":
                    return <ul key={index}>{children}</ul>;
                case "li":
                    return <li key={index}>{children}</li>;
                case "strong":
                    return <strong key={index}>{children}</strong>;
                case "br":
                    return <br key={index} />;
                case "a":
                    return (
                        <span key={index}>
                            {children} {t("(Vorschaulink)")}
                        </span>
                    );
                default:
                    return null;
            }
        });
    return (
        <div className="template-preview">
            {nodes(document.body.childNodes)}
        </div>
    );
}
