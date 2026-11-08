"""After the store moves up a schema: fill the new columns for what is already
stored, from the pages already kept (no fetching). Run by whichever opens the
store first after an install: a command, or the candidate page."""

from __future__ import annotations

from drafter import candidates
from drafter.feeds import nvd
from drafter.store import Store


def fill(store: Store) -> str | None:
    """What was filled, or None if the store didn't just move up."""
    if not store.migrated_from:  # None: it didn't move; 0: a new, empty store
        return None
    vendor = candidates.reparse(store)
    rows = nvd.reparse_products(store)
    return (
        f"store upgraded from schema {store.migrated_from}: NVD rows filled for {rows} CVE(s),"
        f" vendor records re-read: {vendor}"
    )
