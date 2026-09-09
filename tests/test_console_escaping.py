"""
Everything the analyst console renders is attacker-influenced.

`target` is a resource id or IP copied verbatim from the finding, so anyone who
can name an EC2 instance, an IAM user or an S3 object chooses that string.
`finding_type` comes from the detector. The three `*_summary` fields are LLM
prose derived from the same finding. All of it was interpolated straight into
`innerHTML`.

That is stored XSS, and the blast radius is unusually bad: this console *is* the
governance surface, and it keeps the operator's APPROVE/PROMOTE token in
`sessionStorage`. Script running here can approve its own containment actions,
or promote an action class to auto-execute — turning the defence system into the
attack. Verified against a running console before the fix (three injected `<img>`
elements, handler fired six times) and after (zero, payload rendered as text).

The fix is a tagged template that escapes every interpolation by default, so the
next render is safe without anyone remembering. These tests guard that default,
because the failure mode is one forgotten `escape()` in one new line of markup —
which is exactly how it happened: the codebase already HAD an `escapeHtml`
helper, used in precisely one place.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parent.parent / "kronagent" / "static" / "app.js"


@pytest.fixture(scope="module")
def source() -> str:
    return APP_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lines(source: str) -> list[str]:
    return source.split("\n")


def test_the_escaping_helpers_exist(source: str):
    """If these are renamed, every assertion below silently stops meaning
    anything, so they are asserted explicitly rather than assumed."""
    assert "class SafeHtml" in source
    assert "const h = (strings, ...values)" in source
    assert "const raw = (value)" in source


def test_the_escape_covers_every_character_that_can_break_out(source: str):
    """`<` and `>` alone are not enough. A value interpolated into an unquoted
    or single-quoted attribute escapes with `"` or `'`; a backtick can start a
    template literal in some injection contexts.

    The behavioural tests below are the real check — this one names the
    characters so a regression says which one was dropped.
    """
    body = source[source.index("const escapeHtml"):source.index("const h =")]
    for char in ("&", "<", ">", '"', "'", r"\x60"):
        assert f'"{char}"' in body or f"'{char}'" in body, (
            f"escapeHtml does not handle {char!r}")


def test_the_source_has_no_backtick_outside_a_template_literal(source: str):
    """The assumption the scanner below depends on, asserted rather than
    assumed.

    A backtick inside a regex literal or a comment is indistinguishable from a
    template delimiter to a character scanner, and one stray backtick shifts
    every pairing after it — turning the invariant into noise, or worse, into a
    silent pass. `escapeHtml`'s own character class contained one; it is written
    `\\x60` now for exactly this reason.

    An odd count is proof of a stray. An even count is not proof of none, so the
    scanner's own self-check (that it still sees the approval card) covers the
    rest.
    """
    assert source.count("`") % 2 == 0, (
        "odd number of backticks — a regex literal or comment almost certainly "
        "contains one, and the template scanner cannot pair them correctly")


def test_every_innerhtml_assignment_uses_the_tagged_template(lines: list[str]):
    """The one rule that makes the rest unnecessary to remember.

    A bare backtick after `innerHTML =` is an unescaped render. This is the
    check that would have caught the original defect on the day it was written.
    """
    offenders = [
        f"{n}: {ln.strip()[:90]}"
        for n, ln in enumerate(lines, 1)
        if re.search(r"\.innerHTML\s*=\s*`", ln)
    ]
    assert not offenders, (
        "innerHTML assigned from an untagged template literal — every "
        "interpolation there is unescaped:\n  " + "\n  ".join(offenders)
        + "\nUse h`...` instead."
    )


def _markup_templates(source: str) -> list[tuple[int, bool, str]]:
    r"""Every template literal that emits an element, as (line, tagged, preview).

    Scans character by character, tracking `${...}` nesting and backslash
    escapes, so a template spanning twenty lines is one template rather than
    twenty independent lines. That distinction is the whole point: the approval
    card — the single most important render in the file — opens with a bare
    `return \`` and puts its first tag on the NEXT line. A line-oriented check
    walked straight past it, which mutation testing caught only because the
    mutation was applied to that exact template.
    """
    out: list[tuple[int, bool, str]] = []
    i, n = 0, len(source)
    while i < n:
        if source[i] != "`":
            i += 1
            continue
        tagged = i > 0 and source[i - 1] == "h"
        line = source.count("\n", 0, i) + 1
        j, depth, body = i + 1, 0, []
        while j < n:
            c = source[j]
            if c == "\\":
                j += 2
                continue
            if c == "$" and j + 1 < n and source[j + 1] == "{":
                depth += 1
                j += 2
                continue
            if c == "}" and depth:
                depth -= 1
                j += 1
                continue
            if c == "`" and depth == 0:
                break
            if depth == 0:
                body.append(c)
            j += 1
        text = "".join(body)
        if re.search(r"<[a-zA-Z][a-zA-Z0-9]*[\s/>]", text):
            out.append((line, tagged, text.strip()[:70]))
        # Continue *after* this template so a nested one is not re-scanned as a
        # sibling; nested templates are visited by their own ${...} content.
        i = j + 1
    return out


def test_every_markup_template_is_tagged(source: str):
    """The rule, applied to whole templates rather than single lines.

    A helper returning raw markup is laundered through whatever embeds it.
    `stageDesc` was built that way from audit-payload fields — `target`,
    `operator_id`, `detail` — and then interpolated into the timeline.
    """
    offenders = [f"line {ln}: {preview}"
                 for ln, tagged, preview in _markup_templates(source) if not tagged]
    assert not offenders, (
        "template literals emitting markup without the h`` tag — every "
        "interpolation in them is unescaped:\n  " + "\n  ".join(offenders)
    )


def test_the_scanner_actually_sees_the_approval_card(source: str):
    """A scanner that finds nothing passes vacuously.

    The approval card is the render that carries `target` and the model-written
    summaries, so if it is not among the templates examined, the test above is
    decoration.
    """
    found = [preview for _, _, preview in _markup_templates(source)]
    assert any("request-card" in p for p in found), (
        "the approval card template was not scanned")
    assert len(found) >= 10, f"only {len(found)} markup templates found"


def test_raw_is_only_used_on_markup_this_file_composed(lines: list[str]):
    """`raw()` is the deliberate escape hatch, so every use must be auditable.

    It is legitimate for joining already-escaped fragments (`.map(x => h\\`…\\`)`)
    and illegitimate for anything that reaches for server data directly. A
    `raw(req.something)` would reintroduce the whole defect through the one door
    left open on purpose.
    """
    server_data = ("req.", "entry.", "payload.", "event.", "state.", "m.", "c.")
    offenders = []
    for n, ln in enumerate(lines, 1):
        for match in re.finditer(r"\braw\(([^)]*)", ln):
            arg = match.group(1)
            # Joining escaped fragments is the sanctioned use.
            if ".map(" in arg and "h`" in ln:
                continue
            if arg.strip().startswith(server_data):
                offenders.append(f"{n}: raw({arg[:60]}")
    assert not offenders, (
        "raw() applied directly to server data, which bypasses escaping:\n  "
        + "\n  ".join(offenders)
    )


# --- Behavioural: the escaping actually escapes ------------------------------
#
# The structural tests above prove every render goes through `h`. These prove
# `h` is worth going through. Both halves are needed: either alone is an
# argument with a hole in it.
#
# An earlier version of this file tried to check individual fields by walking
# back from `${req.target}` to the nearest backtick and asserting it was
# preceded by `h`. That heuristic cannot tell an opening backtick from a closing
# one — it reported a false positive on a correctly-tagged line — and a check
# that can produce a false alarm can equally produce a false pass. Running the
# real helper is both simpler and sound.

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="needs node to run app.js")

PAYLOADS = [
    '<img src=x onerror="alert(1)">',          # the classic element injection
    '"><script>alert(1)</script>',             # break out of an attribute
    "' onmouseover='alert(1)",                 # single-quoted attribute
    "`${alert(1)}`",                           # backtick / template literal
    "javascript:alert(1)",                     # scheme, must survive as text
]


def _run_in_node(script: str) -> str:
    res = subprocess.run([NODE, "-e", script], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    return res.stdout


def _helper_source(source: str) -> str:
    """The real helper block, lifted from app.js rather than reimplemented.

    A copy in the test would pass forever while the shipped helper rotted.
    """
    start = source.index("class SafeHtml")
    marker = "out + chunk + (i < values.length ? escapeHtml(values[i]) : \"\"), \"\"));"
    end = source.index(marker) + len(marker)
    block = source[start:end]
    # Guard the extraction itself: a silently-truncated block would define no
    # `h`, node would throw, and _run_in_node's returncode assertion would fail
    # loudly — but a block that over-reaches still runs, and quietly tests more
    # than it claims to.
    assert block.count("class SafeHtml") == 1
    assert "const h = (strings" in block
    assert "updateOversightUI" not in block, "extraction ran past the helpers"
    return block


@needs_node
@pytest.mark.parametrize("payload", PAYLOADS)
def test_the_tagged_template_neutralises_real_payloads(source: str, payload: str):
    """Run app.js's own helper over payloads an attacker can place in a resource
    name, and assert nothing survives that a browser would treat as markup."""
    script = rf"""
{_helper_source(source)}
const payload = {json.dumps(payload)};
const out = String(h`<h3>${{payload}} on <code>${{payload}}</code></h3>`);
if (/<(img|script)\b/i.test(out)) {{ console.log("ELEMENT_SURVIVED"); }}
else if (out.includes('"') || out.includes("'") || out.includes("`")) {{
    console.log("QUOTE_SURVIVED");
}} else {{ console.log("SAFE:" + out); }}
"""
    result = _run_in_node(script).strip()
    assert result.startswith("SAFE:"), f"{payload!r} -> {result}"
    # The value must still be *visible* — an analyst needs to see that a
    # resource is maliciously named, they just must not execute it.
    assert "alert" in result or "javascript" in result


@needs_node
def test_raw_deliberately_does_not_escape(source: str):
    """`raw()` is the escape hatch, and it must really be one — otherwise
    composed fragments render as visible literal markup and someone 'fixes'
    that by removing the escaping."""
    script = rf"""
{_helper_source(source)}
console.log(String(h`<ul>${{raw("<li>ok</li>")}}</ul>`));
"""
    assert "<li>ok</li>" in _run_in_node(script)


@needs_node
def test_nested_tagged_templates_do_not_double_escape(source: str):
    """The approval card nests fragments inside the outer template. If nesting
    double-escaped, every rendered card would show literal `&lt;p&gt;` — which
    is the pressure that makes someone reach for innerHTML again."""
    script = rf"""
{_helper_source(source)}
const inner = h`<p>${{"a & b"}}</p>`;
console.log(String(h`<div>${{inner}}</div>`));
"""
    out = _run_in_node(script)
    assert "<div><p>a &amp; b</p></div>" in out, out


def test_the_operator_token_is_still_only_in_session_storage(source: str):
    """Context for the severity above, and a guard on it.

    The token lives in sessionStorage, so any script executing in this page can
    read it. That is acceptable only while nothing attacker-controlled can
    execute here — which is what the tests above are for. If the token ever
    moves somewhere more durable, the exposure outlives the tab.
    """
    assert "localStorage.setItem(\"kronagent_operator_token\"" not in source, (
        "the operator token moved to localStorage, where it survives the tab "
        "and every future XSS in this origin")
    assert 'sessionStorage.setItem("kronagent_operator_token"' in source
