"""The tool counts in prose match the server.

Four documents and one module docstring state how many tools this server has.
They drifted the moment the surface changed, and a stale "241 tools" in the
README is the kind of thing nobody notices for months. The same drift hit
``instances.py`` (a pre-collapse "240 tool call sites" claim) and the
``server.py``/``fortios_client.py`` docstrings (a patch-level "7.6.6" the
fleet cannot guarantee), so those claims are pinned here too.

``CLAUDE.md`` is deliberately excluded from ``DOCS``: it is listed in
``.git/info/exclude`` alongside ``.claude/`` and ``.mcp.json``, so a fresh
clone (including CI) has no such file on disk. Reading it here would turn
every CI run into a ``FileNotFoundError``.
"""

from __future__ import annotations

import re
from pathlib import Path

from server import mcp

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("README.md", "CONTRIBUTING.md")

#: Counts that were true before the collapse and must not survive in prose.
STALE_NUMBERS = ("241", "231", "183 of the 241", "~200 typed")


async def test_the_server_registers_the_expected_number_of_tools() -> None:
    assert len(await mcp.list_tools()) == 91


def test_no_document_still_claims_a_pre_collapse_count() -> None:
    offenders: list[str] = []
    for name in DOCS:
        text = (ROOT / name).read_text(encoding="utf-8")
        for stale in STALE_NUMBERS:
            if stale in text:
                offenders.append(f"{name}: {stale!r}")
    annotations = (ROOT / "tool_annotations.py").read_text(encoding="utf-8")
    for stale in ("241", "183 of 241"):
        if stale in annotations:
            offenders.append(f"tool_annotations.py: {stale!r}")
    assert offenders == [], f"stale tool counts in prose: {offenders}"


def test_readme_states_the_current_count() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "91" in text, "README should state the current tool count"


def test_instructions_no_longer_name_a_removed_tool() -> None:
    """``system_status`` folded into ``system_read``."""
    text = (ROOT / "server.py").read_text(encoding="utf-8")
    instructions = text[text.index("instructions=(") :]
    assert "system_status" not in instructions
    assert "system_read" in instructions


def test_no_module_docstring_pins_a_patch_level_firmware_version() -> None:
    """The fleet may run mixed firmware; prose says "7.6", never "7.6.6"."""
    offenders: list[str] = []
    for name in ("server.py", "fortios_client.py"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for match in re.findall(r"7\.6\.\d+", text):
            offenders.append(f"{name}: {match!r}")
    assert offenders == [], f"patch-level version claims in prose: {offenders}"


async def test_instances_docstring_cites_the_real_instance_tool_count() -> None:
    """``ErrorClient``'s docstring justifies ``resolve()`` with a tool count."""
    tools = await mcp.list_tools()
    with_instance = [
        t for t in tools if "instance" in (t.inputSchema.get("properties") or {})
    ]
    text = (ROOT / "instances.py").read_text(encoding="utf-8")
    cited = re.search(r"the (\d+) tools that take an ``instance`` parameter", text)
    assert cited is not None, (
        "instances.py should cite how many tools take an instance parameter"
    )
    assert int(cited.group(1)) == len(with_instance)


async def test_annotation_category_counts_match_reality() -> None:
    """The docstring in ``tool_annotations.py`` cites per-category counts."""
    tools = await mcp.list_tools()
    readers = [t for t in tools if t.annotations and t.annotations.readOnlyHint]
    writers = [t for t in tools if t.annotations and not t.annotations.readOnlyHint]
    assert len(readers) + len(writers) == 91
    text = (ROOT / "tool_annotations.py").read_text(encoding="utf-8")
    cited = re.search(r"(\d+) of (\d+) tools", text)
    assert cited is not None, "tool_annotations.py should cite N of M tools"
    assert int(cited.group(2)) == 91
    assert int(cited.group(1)) == len(readers)


def test_count_param_description_cites_the_real_default() -> None:
    """``CountParam``'s prose ("default 50") must track ``PAGE_ROWS``.

    A stale default here directly misleads the model calling the tool, not
    just a human reading docs.
    """
    import typing

    from paging import PAGE_ROWS
    from tool_params import CountParam

    field_info = typing.get_args(CountParam)[1]
    assert str(PAGE_ROWS) in (field_info.description or ""), (
        "CountParam's description no longer cites the real PAGE_ROWS default"
    )


def test_readme_cites_the_real_page_row_default() -> None:
    from paging import PAGE_ROWS

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"most {PAGE_ROWS} rows" in text, (
        "README's paging bullet no longer cites the real PAGE_ROWS default"
    )


def test_readme_cites_the_real_char_budget() -> None:
    from paging import PAGE_CHAR_BUDGET

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{PAGE_CHAR_BUDGET:,}" in text, (
        "README's paging bullet no longer cites the real PAGE_CHAR_BUDGET"
    )
