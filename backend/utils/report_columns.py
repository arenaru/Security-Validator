"""
Per-module column specs for the XLSX report.

The generated sheet for a module should match what the UI shows for that same
module, so a report reader and a screen reader see the same table. These specs
mirror ``getColumnsForModule`` in ``frontend/src/components/ResultsTable.tsx``.

NOTE: this duplicates the column definitions that live in TypeScript. Keeping a
single source of truth would mean serving the spec from the backend and having
the UI render from it, which couples the UI to a backend contract — not worth it
for 14 modules. If you change a module's columns in ResultsTable.tsx, change
them here too; ``backend/tests/test_xlsx_report.py`` pins the headers so a drift
shows up as a failing test rather than a silently wrong report.
"""
from __future__ import annotations

from typing import Any

# Header used for the generated 1..N row counter (the UI's "#" column).
ROW_NUMBER_HEADER = "No"

# Marker for a column whose value is generated rather than read from the payload.
_GENERATED: tuple[str, ...] = ()

# module name -> ((header, raw-key fallbacks), ...)
#
# The key tuples mirror the UI's getRaw(item, 'A', 'B', ...) lookup order: the
# first key present in the payload wins.
MODULE_COLUMNS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "Response Code Check": (
        (ROW_NUMBER_HEADER, _GENERATED),
        ("URL", ("URL", "url", "target", "Target")),
        ("Status Code", ("Status Code",)),
        ("Final Code", ("Final Code",)),
        ("Final URL", ("Final URL",)),
        ("Message", ("Message",)),
    ),
}

# Columns holding an HTTP status code, which get the same emerald/amber/slate
# treatment as the UI badges. Keyed by module so a "Status Code" column in an
# unrelated module is not coloured by accident.
HTTP_CODE_COLUMNS: dict[str, frozenset[str]] = {
    "Response Code Check": frozenset({"Status Code", "Final Code"}),
}

# Fallback shape for modules without a spec: the original generic columns.
GENERIC_COLUMNS: tuple[str, ...] = (
    "module",
    "target",
    "status",
    "details",
    "vuln_name",
)


def resolve_cell(raw: dict[str, Any] | None, keys: tuple[str, ...]) -> Any:
    """
    Return the first key present in ``raw``, mirroring the UI's getRaw().

    Presence is tested with ``in`` rather than truthiness so a legitimate 0 or
    empty string is not skipped in favour of a later fallback key.
    """
    if not raw:
        return None
    for key in keys:
        if key in raw:
            return raw[key]
    return None


def code_fill_bucket(value: Any) -> str:
    """
    Classify an HTTP code for fill purposes: "error" (4xx/5xx), "ok" (anything
    else that answered), or "none" when there is no code at all.

    "none" is its own bucket so an unreachable host is not tinted green.
    """
    text = str(value if value is not None else "").strip()
    if not text or text in {"-", "N/A"}:
        return "none"
    return "error" if text[:1] in {"4", "5"} else "ok"
