# core/diff.py — visit-to-visit audit comparison
import datetime


SEV_RANK = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def diff_audits(current: list, previous: list) -> dict:
    """
    Compare current audit results against the previous visit's snapshot.
    Returns categorized changes: new, fixed, worsened, still_open.
    """
    if not previous:
        return {"has_previous": False}

    curr_map = {r.get("label"): r for r in current}
    prev_map = {r.get("label"): r for r in previous}

    new_findings  = []
    fixed         = []
    worsened      = []
    still_open    = []

    for label, curr in curr_map.items():
        prev = prev_map.get(label)
        if not prev:
            continue  # New check type — no baseline to compare

        curr_sev = SEV_RANK.get(curr.get("severity", "ok"), 3)
        prev_sev = SEV_RANK.get(prev.get("severity", "ok"), 3)

        curr_findings = set(str(f) for f in curr.get("findings", []))
        prev_findings = set(str(f) for f in prev.get("findings", []))

        appeared = curr_findings - prev_findings
        resolved = prev_findings - curr_findings

        for f in appeared:
            new_findings.append({"label": label, "finding": f, "severity": curr.get("severity", "ok")})

        for f in resolved:
            fixed.append({"label": label, "finding": f})

        if curr_sev < prev_sev and not appeared:
            worsened.append({"label": label, "severity": curr.get("severity", "ok")})

        if not appeared and not resolved and curr_sev < 3 and curr_sev == prev_sev:
            still_open.append({"label": label, "severity": curr.get("severity", "ok")})

    return {
        "has_previous": True,
        "new":          new_findings,
        "fixed":        fixed,
        "worsened":     worsened,
        "still_open":   still_open,
    }


def format_diff(diff: dict, client_name: str = "", visit_date: str = "") -> str:
    if not diff.get("has_previous"):
        return "[No previous audit on record — this will be the baseline for next visit.]"

    lines = [
        f"VISIT DIFF — {client_name or 'Unknown'}",
        f"Compared to last visit: {visit_date or 'previous'}",
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "=" * 55,
        "",
    ]

    new     = diff.get("new", [])
    fixed   = diff.get("fixed", [])
    worse   = diff.get("worsened", [])
    still   = diff.get("still_open", [])

    if new or worse:
        lines.append("🔴 NEW / WORSENED since last visit:")
        for item in sorted(new, key=lambda x: SEV_RANK.get(x.get("severity", "ok"), 3)):
            sev = item.get("severity", "").upper()
            lines.append(f"   [{sev}] {item['label']}: {item['finding']}")
        for item in worse:
            lines.append(f"   [{item['severity'].upper()}] {item['label']} got worse")
        lines.append("")

    if fixed:
        lines.append("✅ FIXED since last visit:")
        for item in fixed:
            lines.append(f"   {item['label']}: {item['finding']}")
        lines.append("")

    if still:
        lines.append("⚠️  Still open from last time (not fixed):")
        for item in sorted(still, key=lambda x: SEV_RANK.get(x.get("severity", "ok"), 3)):
            lines.append(f"   [{item['severity'].upper()}] {item['label']}")
        lines.append("")

    if not new and not worse and not fixed and not still:
        lines.append("✅ No changes detected from last visit.")

    return "\n".join(lines)
