"""HTML redline diff (original vs masked) for dry-run policy sign-off."""
from __future__ import annotations

import difflib
import html

_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Redline preview — {file_id}</title>
<style>
 body {{ font-family: ui-monospace, Consolas, monospace; margin: 2rem; line-height: 1.7;
        max-width: 60rem; }}
 h1 {{ font-family: system-ui, sans-serif; font-size: 1.2rem; }}
 .meta {{ color: #555; font-family: system-ui, sans-serif; font-size: .85rem;
          margin-bottom: 1.5rem; }}
 del {{ background: #ffd6d6; color: #8b0000; text-decoration: line-through; padding: 0 2px; }}
 ins {{ background: #d6f5d6; color: #05500a; text-decoration: none; padding: 0 2px;
        border-radius: 2px; }}
 pre {{ white-space: pre-wrap; word-break: break-word; border: 1px solid #ddd;
        border-radius: 6px; padding: 1rem; background: #fafafa; }}
</style></head><body>
<h1>Redline preview — {file_id}</h1>
<div class="meta">mode: {mode} &nbsp;|&nbsp; policy: {policy_version} &nbsp;|&nbsp;
 status: {status} &nbsp;|&nbsp; replacements: {count}</div>
<pre>{body}</pre>
</body></html>
"""


def _tokens(s: str) -> list[str]:
    out, cur, ws = [], [], False
    for ch in s:
        if ch.isspace() != ws and cur:
            out.append("".join(cur))
            cur = []
        ws = ch.isspace()
        cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def redline_html(
    original: str,
    masked: str,
    *,
    file_id: str = "",
    mode: str = "",
    policy_version: str = "",
    status: str = "",
    count: int = 0,
) -> str:
    a, b = _tokens(original), _tokens(masked)
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    parts: list[str] = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            parts.append(html.escape("".join(a[i1:i2])))
        else:
            if i2 > i1:
                parts.append(f"<del>{html.escape(''.join(a[i1:i2]))}</del>")
            if j2 > j1:
                parts.append(f"<ins>{html.escape(''.join(b[j1:j2]))}</ins>")
    return _PAGE.format(
        file_id=html.escape(file_id),
        mode=html.escape(mode),
        policy_version=html.escape(policy_version),
        status=html.escape(status),
        count=count,
        body="".join(parts),
    )
