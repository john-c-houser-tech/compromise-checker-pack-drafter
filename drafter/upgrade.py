"""After the store moves up a schema: fill the new columns for what is already
stored, from the pages already kept (no fetching). The move marks the fill as owed
(the `refill` table) and this clears it when done, so a fill cut short (the page
restarted, the store busy) is done again by the next command or page start."""

from __future__ import annotations

from drafter import candidates
from drafter.feeds import nvd
from drafter.store import Store


def fill(store: Store) -> str | None:
    """What was filled, or None if nothing was owed."""
    owed = [row[0] for row in store.db.execute("SELECT schema FROM refill ORDER BY schema")]
    if not owed:
        return None
    vendor = candidates.reparse(store)
    rows = nvd.reparse_products(store)
    with store.transaction():
        store.db.execute("DELETE FROM refill")
    return (
        f"store filled for schema {owed[-1]} from the pages already kept: NVD rows for"
        f" {rows} CVE(s), vendor records re-read: {vendor}"
    )
