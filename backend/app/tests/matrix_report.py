"""Collects what the matrix test observed and renders it as a table.

The test records into RESULTS; conftest.pytest_terminal_summary prints it, so
the table shows up in a normal `pytest` run (no -s needed).
"""

ROLE_ORDER = ("admin", "warehouse", "field", "auditor")

# (capability, role) -> (actual HTTP status, expected HTTP status)
RESULTS: dict[tuple[str, str], tuple[int, int]] = {}


def _cell(actual: int, expected: int) -> str:
    if actual != expected:
        return f"FAIL {actual} (want {expected})"
    return "ALLOW 200" if actual == 200 else f"deny {actual}"


def render() -> list[str]:
    caps = list(dict.fromkeys(cap for cap, _ in RESULTS))
    width = max(len(c) for c in caps)
    cell_w = max(len(_cell(*RESULTS[k])) for k in RESULTS)
    head = "capability".ljust(width) + "  " + "  ".join(r.ljust(cell_w) for r in ROLE_ORDER)
    lines = [head, "-" * len(head)]
    for cap in caps:
        cells = [
            _cell(*RESULTS[(cap, r)]).ljust(cell_w) if (cap, r) in RESULTS else "-".ljust(cell_w)
            for r in ROLE_ORDER
        ]
        lines.append(cap.ljust(width) + "  " + "  ".join(cells))
    bad = sum(1 for a, e in RESULTS.values() if a != e)
    lines.append("")
    lines.append(f"{len(RESULTS)} role/capability checks, {bad} mismatches")
    return lines
