# dmarc-stats

Cet utilitaire permet d’identifier les erreurs communes à partir d’un ensemble
de rapports DMARC agrégés par
[`parsedmarc`](https://pypi.org/project/parsedmarc/) dans un fichier `JSON`.

## Installation

Vous aurez besoin du petit utilitaire
[`uv`](https://docs.astral.sh/uv/getting-started/installation/) sur votre
système.

## Utilisation

```console
# Générer le rapport aggrégé à partir d’une copie locale du dossier IMAP
# recevant les rapports DMARC.
uv run parsedmarc --silent --offline ~/path/to/mailbox/email* --output output

# Analyser les rapports reçus.
uv run dmarc-stats output/aggregate.json
# Analyser les rapports reçus depuis la date spécifiée (format ISO8601).
uv run dmarc-stats output/aggregate.json --since 2024-10-01
```
