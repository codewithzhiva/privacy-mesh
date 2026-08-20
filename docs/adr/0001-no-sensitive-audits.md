# ADR 0001: Sensitive values never enter audits

Status: accepted. Audits store only entity categories, action counts, and non-reversible short fingerprints. Raw matches are used transiently for redaction and then discarded.
