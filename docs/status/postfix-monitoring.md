# Postfix und Mailqueue

Der feste lokale Adapter liest postqueue -j mit Zeit-, Zeilen- und Größenlimit. Er persistiert ausschließlich Anzahl, Deferred-Anteil, Alter der ältesten zurückgestellten Nachricht und einen lokalen Ready-Zustand. Keine Adressen, Queue-IDs, Betreffzeilen oder Inhalte. Er wird durch den bestehenden privaten Healthcheck angestoßen und schreibt atomar in seinen eigenen Mount. Die API liest diesen Mount nur read-only. Ein ausgefallener Adapter ergibt unknown, kein Healthy. Keine Testmail, Queue-Löschung oder Neuzustellung. Eine leere Queue ist keine Zustellgarantie.
