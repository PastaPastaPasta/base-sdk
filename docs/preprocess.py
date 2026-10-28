#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Pre-processing used before generating Zensical documentation."""

from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from typing import TYPE_CHECKING

from common import off_disk, root_dir, spelt_as_stored
from markdown.blockprocessors import (
  ListIndentProcessor,
  OListProcessor,
  UListProcessor,
)
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor

if TYPE_CHECKING:
  from collections.abc import Iterator

  from markdown import Markdown

# Admonition each alert kind is rendered as.
_ALERT_KIND = {
  "NOTE": "note",
  "TIP": "tip",
  "IMPORTANT": "info",
  "WARNING": "warning",
  "CAUTION": "danger",
}

# Matches the marker opening a GitHub-flavoured alert.
_ALERT_RE = re.compile(
  r"^>[ ]?\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ ]*(.*)$"
)

# Matches a line carrying the body of a block quote.
_QUOTE_LINE_RE = re.compile(r"^>[ ]?(.*)$")


class GfmAlertsPreprocessor(Preprocessor):
  """Rewrite `> [!NOTE]` blocks into admonition syntax."""

  def run(self, lines: list[str]) -> list[str]:
    source = list(lines)
    output: list[str] = []
    index = 0
    fences = _Fences()

    while index < len(source):
      line = source[index]
      # An alert shown inside a fence is an example, not a callout.
      match = None if fences.covers(line) else _ALERT_RE.match(line)
      if match is None:
        output.append(line)
        index += 1
        continue

      level = _ALERT_KIND[match.group(1)]
      output.append(f"!!! {level}")

      first_line = match.group(2).strip()
      body: list[str] = []
      if first_line:
        body.append(first_line)

      index += 1
      while index < len(source):
        quoted = _QUOTE_LINE_RE.match(source[index])
        if quoted is None:
          break
        body.append(quoted.group(1))
        index += 1

      if not body:
        output.append("    ")
        continue

      for body_line in body:
        if body_line:
          output.append(f"    {body_line}")
        else:
          output.append("    ")

    return output


# Matches a code block, and whatever trails the marker on that line.
_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")

# Info string of a fence holding a directive as the syntax being shown.
_LITERAL_INFO = "text"

# Matches a splice from another file, or one named section from it.
_INCLUDE_RE = re.compile(r"^(\s*)<!--\s*\[include:([^\]]+)\]\s*-->\s*$")

# Matches any directive-shaped comment, by the verb and label it names.
_DIRECTIVE_RE = re.compile(r"^\s*<!--\s*\[([A-Za-z]+):[^\]]*\]\s*-->\s*$")

# The directives this module answers for. Anything else is a misspelling.
_DIRECTIVES = frozenset({"include", "start", "end"})

# Label reserved for a segment the site does not carry.
_OMIT_LABEL = "omit"

# Matches a bound of such a segment.
_OMIT_RE = re.compile(rf"^\s*<!--\s*\[(start|end):{_OMIT_LABEL}\]\s*-->\s*$")

# Matches a line holding a marker.
_MARKER_ONLY_RE = re.compile(
  r"^[\s/*#<>!;%-]*\[(?:start|end):[^\]]+\][\s/*#<>!;%-]*$"
)

# Matches the target of an inline link, and any title trailing it.
_LINK_RE = re.compile(
  r"\]\(\s*(<[^<>]*>|[^\s()]+)"
  r"((?:\s+(?:\"[^\"]*\"|'[^']*'|\([^()]*\)))?\s*)\)"
)

# Directory holding this extension, which is the documentation root.
_DOCS_ROOT = Path(__file__).resolve().parent

# Suffix of a file that is prose, and so a page rather than a quotation.
_PAGE_SUFFIX = ".md"

# Stems Zensical serves as a directory's own index, matched as spelt here.
_INDEX_STEMS = frozenset({"README", "index"})

# How many includes may nest before the splice is called a cycle.
_DEPTH_LIMIT = 8


def _strip_omitted(lines: list[str]) -> list[str]:
  """Return *lines* without any segment labelled for omission."""
  output: list[str] = []
  fences = _Fences()
  begin = None

  for index, line in enumerate(lines):
    # An omitted line never reaches the renderer, so it cannot open a fence in
    # the stream *fences* models and is not tracked in it.
    hidden = begin is not None
    found = _OMIT_RE.match(line) if hidden or not fences.covers(line) else None
    if found is None:
      if not hidden:
        # A misspelt verb doesn't match, so the line is passed on and
        # refused in `_named_directive`.
        output.append(line)
      continue
    if found.group(1) == "start":
      if hidden:
        raise ValueError(f"{_OMIT_LABEL}: segments do not nest")
      begin = index
      continue
    if not hidden:
      raise ValueError(f"{_OMIT_LABEL}: no segment is open")
    if _opens_a_fence(lines[begin + 1 : index]):
      raise ValueError(f"{_OMIT_LABEL}: segment leaves a fence open")
    begin = None

  if begin is not None:
    raise ValueError(f"{_OMIT_LABEL}: segment left open")
  return output


def _named_directive(line: str) -> None:
  """Raise when *line* holds a directive this module does not answer for."""
  found = _DIRECTIVE_RE.match(line)
  if found is not None and found.group(1) not in _DIRECTIVES:
    raise ValueError(f"{found.group(1)}: no such directive")


class _Fences:
  """Running fence state over a sequence of lines."""

  def __init__(self, opener: str | None = None, info: str = "") -> None:
    self.opener = opener
    self.info = info

  @property
  def literal(self) -> bool:
    """Whether the open fence shows a directive rather than using it."""
    return self.opener is not None and self.info == _LITERAL_INFO

  def covers(self, line: str) -> bool:
    """Whether *line* is fenced, counting the fence markers themselves."""
    marker = _FENCE_RE.match(line)
    if marker is None:
      return self.opener is not None
    found, trailing = marker.group(1), marker.group(2)
    if self.opener is None:
      self.opener = found
      self.info = trailing.strip()
    # A closing fence carries no info string, so a marker that does is
    # content the block holds rather than the end of it.
    elif (
      found[0] == self.opener[0]
      and len(found) >= len(self.opener)
      and not trailing.strip()
    ):
      self.opener = None
      self.info = ""
    return True


def _opens_a_fence(lines: list[str]) -> bool:
  """Whether *lines* leave a code fence open at their end."""
  fences = _Fences()
  for line in lines:
    fences.covers(line)
  return fences.opener is not None


def _quoted(lines: list[str]) -> list[str]:
  """Return *lines* as code, at their own margin and without markers.

  A region may hold the bounds of another, which name a segment rather
  than the code the reader is being shown.
  """
  kept = (line for line in lines if not _MARKER_ONLY_RE.match(line))
  return dedent("\n".join(kept)).strip("\n").splitlines()


def forge_url(repo_url: str, branch: str, source: Path) -> str:
  """Return the URL *source* is served from, by its kind."""
  kind = "tree" if source.is_dir() else "blob"
  where = source.relative_to(root_dir())
  return f"{repo_url}/{kind}/{branch}/{where}"


class IncludePreprocessor(Preprocessor):
  """Splice in a file and parse disk-local links.

  A link is relative to the file holding it, so a link carried in from elsewhere
  in the repository cannot be served from the site and is pointed at the
  upstream host instead.
  """

  def __init__(self, md: Markdown, repo_url: str, branch: str) -> None:
    super().__init__(md)
    self.repo_url = repo_url.rstrip("/")
    self.branch = branch

  def run(self, lines: list[str]) -> list[str]:
    return self._expand(_strip_omitted(lines), _DEPTH_LIMIT, _Fences())

  def _expand(
    self, lines: list[str], budget: int, fences: _Fences,
  ) -> list[str]:
    """Splice every include in *lines*, recursing *budget* levels deep.

    *fences* is shared across levels because the renderer sees one stream,
    a fence opened by an included file still holds when the parent resumes.
    """
    output: list[str] = []

    for line in lines:
      fences.covers(line)
      # A directive a literal fence holds is the syntax being shown.
      if fences.literal:
        output.append(line)
        continue
      match = _INCLUDE_RE.match(line)
      if match is None:
        _named_directive(line)
        output.append(line)
        continue
      if budget <= 0:
        raise ValueError(f"{match.group(2)}: includes nested past the limit")
      # A directive stands at the margin of whatever holds it, so what it
      # splices in has to be laid out from there and not from column zero.
      margin = match.group(1)
      spliced = self._include(match.group(2), fences, budget)
      output.extend(margin + text if text else text for text in spliced)

    return output

  def _include(self, spec: str, fences: _Fences, budget: int) -> list[str]:
    """Return the lines *spec* names, as the prose or the code they are."""
    name, _, section = spec.partition(":")
    source = (root_dir() / name).resolve()
    # An absolute *name* would displace the root it is joined to, so the
    # containment check has to follow the join rather than precede it.
    if not source.is_relative_to(root_dir()):
      raise ValueError(f"{spec}: outside the repository")
    if not source.is_file():
      raise ValueError(f"{spec}: no such file in the repository")
    prose = source.suffix == _PAGE_SUFFIX
    if not prose and fences.opener is None:
      raise ValueError(f"{spec}: outside a code fence")

    lines = source.read_text(encoding="utf-8").splitlines()
    if prose:
      lines = _strip_omitted(lines)
    if section:
      lines = _section(lines, section, spec)
    if not prose:
      # Code holds no link the site can resolve and no directive it
      # reads, so it stands as stored, at the margin its fence sets.
      return _quoted(lines)

    # `_rebase` walks these same lines, so it takes a copy of the fence
    # state at the splice point rather than advancing the caller's.
    held = _Fences(fences.opener, fences.info)
    spliced = self._rebase(lines, source.parent, held)
    return self._expand(spliced, budget - 1, fences)

  def _rebase(
    self, lines: list[str], home: Path, fences: _Fences,
  ) -> list[str]:
    output: list[str] = []

    for line in lines:
      if fences.covers(line):
        output.append(line)
      else:
        output.append(_LINK_RE.sub(lambda m: self._point(m, home), line))

    return output

  def _point(self, match: re.Match[str], home: Path) -> str:
    target, title = match.group(1), match.group(2)
    caged = target.startswith("<") and target.endswith(">")
    if caged:
      target = target[1:-1]
    if off_disk(target):
      return match.group(0)

    path, mark, rest = target.partition("#")
    # A site-root address resolves against the built site, which only
    # postprocessing can see, so it is left for that pass to anchor.
    if path.startswith("/"):
      return match.group(0)
    source = (home / path).resolve()
    if not source.exists():
      raise ValueError(f"{target}: no such file, relative to {home}")
    if not source.is_relative_to(root_dir()):
      raise ValueError(f"{target}: outside the repository")
    if not spelt_as_stored(root_dir(), source):
      raise ValueError(f"{target}: not spelt as the repository holds it")

    where = f"{self._address(source)}{mark}{rest}"
    return f"]({f'<{where}>' if caged else where}{title})"

  def _address(self, source: Path) -> str:
    """Return where *source* is served from, preferring the site."""
    if source.suffix != ".md" or not source.is_relative_to(_DOCS_ROOT):
      return forge_url(self.repo_url, self.branch, source)

    # A page is addressed from the site root, as the file the link was
    # carried in from says nothing about the page it lands on.
    where = [*source.relative_to(_DOCS_ROOT).parent.parts]
    if source.stem not in _INDEX_STEMS:
      where.append(source.stem)
    return "/" + "".join(f"{part}/" for part in where)


def _section(lines: list[str], name: str, spec: str) -> list[str]:
  """Return the lines between the markers naming *name*."""
  opener = f"[start:{name}]"
  closer = f"[end:{name}]"
  begin = next((i for i, text in enumerate(lines) if opener in text), None)
  finish = next((i for i, text in enumerate(lines) if closer in text), None)
  if begin is None or finish is None or finish < begin:
    raise ValueError(f"{spec}: no such section")
  found = lines[begin + 1 : finish]
  # A fence the segment opens holds over the page it is spliced into,
  # which reads there as the segment having swallowed what follows.
  if _opens_a_fence(found):
    raise ValueError(f"{spec}: segment leaves a fence open")
  return found


# Indentation where CommonMark defines a continued list item.
_LIST_INDENT = 2


def _commonmark_list_indent(md: Markdown) -> None:
  """Rebuild the list processors at CommonMark indentation."""
  kept = md.tab_length
  md.tab_length = _LIST_INDENT
  for processor in md.parser.blockprocessors:
    if isinstance(
      processor, ListIndentProcessor | OListProcessor | UListProcessor
    ):
      processor.__init__(md.parser)
  md.tab_length = kept


class PreprocessorHost(Extension):
  """Markdown extension entrypoint."""

  def __init__(self, **kwargs: object) -> None:
    self.config = {
      "repo_url": ["", "Repository the root-relative links point at"],
      "branch": ["", "Branch those links resolve against"],
    }
    super().__init__(**kwargs)

  def extendMarkdown(self, md: Markdown) -> None:
    include = IncludePreprocessor(
      md,
      str(self.getConfig("repo_url")),
      str(self.getConfig("branch")),
    )
    md.preprocessors.register(include, "include", 32)
    md.preprocessors.register(GfmAlertsPreprocessor(md), "gfm_alerts", 31)
    _commonmark_list_indent(md)


def makeExtension(**kwargs: object) -> PreprocessorHost:
  """Construct the extension."""
  return PreprocessorHost(**kwargs)


# Stand-in forge the tests resolve their fixtures against.
_REPO = "https://forge.test/owner/repo"
_BRANCH = "trunk"


class TestPreprocess:
  """Tests for this module, run with `pytest docs/preprocess.py`."""

  @staticmethod
  def _render(source: str) -> str:
    import markdown

    return markdown.Markdown(
      extensions=[
        PreprocessorHost(repo_url=_REPO, branch=_BRANCH),
        "admonition",
      ],
    ).convert(source)

  @staticmethod
  @contextmanager
  def _scratch(**files: str) -> Iterator[Path]:
    with TemporaryDirectory(dir=root_dir()) as name:
      home = Path(name)
      for stem, text in files.items():
        (home / f"{stem}.md").write_text(text, encoding="utf-8")
      yield home.relative_to(root_dir())

  def test_list_continues_at_the_commonmark_column(self) -> None:
    out = self._render("* lead\n\n  continuation\n")
    assert out.count("<li>") == 1
    assert "continuation" in out.split("</li>")[0]

  def test_alert_becomes_admonition(self) -> None:
    out = self._render("> [!CAUTION]\n> Mind the gap.\n")
    assert 'class="admonition danger"' in out
    assert "Mind the gap." in out

  def test_alert_inside_a_fence_is_left_alone(self) -> None:
    out = self._render("```\n> [!NOTE]\n> Shown, not rendered.\n```\n")
    assert "[!NOTE]" in out
    assert "admonition" not in out

  def test_include_splices_a_section(self) -> None:
    with self._scratch(
      whole="above\n<!-- [start:mid] -->\ninside\n<!-- [end:mid] -->\nbelow\n",
    ) as home:
      out = self._render(f'<!-- [include:{home}/whole.md:mid] -->\n')
    assert "inside" in out
    assert "above" not in out
    assert "below" not in out

  def test_include_refuses_what_it_cannot_carry(self) -> None:
    import pytest

    with self._scratch(whole="nothing marked\n") as home:
      code = self._carve(home, "demo.rs", "fn main() {}\n")
      cases = (
        ("/etc/hosts", "outside the repository"),
        ("../../../../etc/hosts", "outside the repository"),
        (f"{home}/gone.md", "no such file"),
        (f"{home}/whole.md:mid", "no such section"),
        # Code read as prose would be rendered as prose.
        (code, "outside a code fence"),
      )
      for spec, message in cases:
        with pytest.raises(ValueError, match=message):
          self._render(f'<!-- [include:{spec}] -->\n')

  def test_section_refuses_an_unclosed_fence(self) -> None:
    import pytest

    with self._scratch(
      whole="<!-- [start:mid] -->\n```\nsample\n<!-- [end:mid] -->\n",
    ) as home:
      with pytest.raises(ValueError, match="leaves a fence open"):
        self._render(f'<!-- [include:{home}/whole.md:mid] -->\n')

  def test_a_literal_fence_shows_the_directive_it_holds(self) -> None:
    held = [
      "<!-- [include:maint/commit.toml] -->",
      "<!-- [inclde:README.md] -->",
      "<!-- [start:omit] -->",
      "<!-- [end:omit] -->",
    ]
    # Neither read nor refused, so a misspelt verb is text like the rest.
    assert self._pointer().run(["```text", *held, "```"]) == [
      "```text", *held, "```",
    ]

  def test_a_misspelt_directive_is_refused(self) -> None:
    import pytest

    with pytest.raises(ValueError, match="no such directive"):
      self._render("<!-- [inclde:README.md] -->\n")

  def test_a_section_marker_is_a_known_directive(self) -> None:
    out = self._render("<!-- [start:mid] -->\nkept\n<!-- [end:mid] -->\n")
    assert "kept" in out

  def test_include_nests(self) -> None:
    with self._scratch(
      outer='```toml\n<!-- [include:maint/commit.toml] -->\n```\n',
    ) as home:
      out = self._render(f'<!-- [include:{home}/outer.md] -->\n')
    assert "[include:" not in out
    assert "namespace" in out

  def test_include_refuses_a_cycle(self) -> None:
    import pytest

    with self._scratch(loop="") as home:
      spec = f'<!-- [include:{home}/loop.md] -->\n'
      (root_dir() / home / "loop.md").write_text(spec, encoding="utf-8")
      with pytest.raises(ValueError, match="nested past the limit"):
        self._render(spec)

  def test_omit_drops_every_segment_it_labels(self) -> None:
    # Unlike a spliceable label, `omit` repeats. A fence or an include a
    # segment holds goes with it, and the file named, were it read, does
    # not exist and would have been refused.
    out = self._render(
      "one\n<!-- [start:omit] -->\n```\nhidden\n```\n<!-- [end:omit] -->\n"
      "two\n<!-- [start:omit] -->\n"
      "<!-- [include:no/such/file.md] -->\n<!-- [end:omit] -->\nthree\n"
    )
    assert "hidden" not in out
    assert all(word in out for word in ("one", "two", "three"))

  def test_omit_refuses_a_malformed_segment(self) -> None:
    import pytest

    cases = (
      ("<!-- [start:omit] -->\nx\n", "segment left open"),
      ("x\n<!-- [end:omit] -->\n", "no segment is open"),
      ("<!-- [start:omit] -->\n<!-- [start:omit] -->\n", "do not nest"),
      ("<!-- [start:omit] -->\n```\n<!-- [end:omit] -->\n",
       "leaves a fence open"),
      # The label must not carry a misspelt verb past the directive check.
      ("<!-- [statr:omit] -->\n", "no such directive"),
    )
    for source, message in cases:
      with pytest.raises(ValueError, match=message):
        self._render(source)

  def test_omit_applies_to_spliced_material(self) -> None:
    import pytest

    with self._scratch(
      part="carried\n<!-- [start:omit] -->\n"
           "[x](./nope.md)\n<!-- [end:omit] -->\n",
    ) as home:
      out = self._render(f'<!-- [include:{home}/part.md] -->\n')
      with pytest.raises(ValueError, match="no such section"):
        self._render(f'<!-- [include:{home}/part.md:omit] -->\n')
    assert "carried" in out
    assert "nope.md" not in out

  @staticmethod
  def _carve(home: Path, name: str, text: str) -> str:
    """Write *text* to *name* under *home* and return the spec for it."""
    (root_dir() / home / name).write_text(text, encoding="utf-8")
    return f"{home}/{name}"

  def test_code_stands_in_the_fence_holding_it(self) -> None:
    body = (
      "fn skipped() {}\n"
      "  // [start:shown]\n"
      "  fn shown() {\n"
      "    // [start:inner]\n"
      "    let x = 1;\n"
      "    // [end:inner]\n"
      "  }\n"
      "  // [end:shown]\n"
    )
    def fenced(spec: str, margin: str = "") -> list[str]:
      return [
        f"{margin}```rust",
        f"{margin}<!-- [include:{spec}] -->",
        f"{margin}```",
      ]

    with self._scratch() as home:
      spec = self._carve(home, "demo.rs", body)
      whole = self._pointer().run(fenced(spec))
      region = self._pointer().run(fenced(f"{spec}:shown"))
      held = self._pointer().run(fenced(f"{spec}:shown", "    "))
    # A marker names a segment rather than the code being shown, so it is
    # dropped wherever it falls, and a region is read at its own margin.
    assert whole == [
      "```rust",
      "fn skipped() {}",
      "  fn shown() {",
      "    let x = 1;",
      "  }",
      "```",
    ]
    assert region == [
      "```rust",
      "fn shown() {",
      "  let x = 1;",
      "}",
      "```",
    ]
    # A fence the page indents, such as one a content tab holds, carries
    # the code it shows at that margin rather than at column zero.
    assert held == ["    " + line for line in region]

  def test_a_link_is_rebased_in_every_form_it_is_written(self) -> None:
    blob = f"{_REPO}/blob/{_BRANCH}"
    cases = (
      ('[a](../README.md "root")',
       (f'href="{blob}/README.md"', 'title="root"')),
      ("[a](<../README.md>)", (f'href="{blob}/README.md"',)),
      ("[a](../maint/commit.toml)", (f'href="{blob}/maint/commit.toml"',)),
    )
    for source, expected in cases:
      with self._scratch(page=f"{source}\n") as home:
        out = self._render(f'<!-- [include:{home}/page.md] -->\n')
      for fragment in expected:
        assert fragment in out, source

  def test_page_under_docs_is_addressed_from_the_site(self) -> None:
    with self._scratch(page="[a](../docs/dev/guide_rust.md)\n") as home:
      out = self._render(f'<!-- [include:{home}/page.md] -->\n')
    assert 'href="/dev/guide_rust/"' in out

  def test_off_disk_link_is_left_alone(self) -> None:
    with self._scratch(page="[a](tel:+15551212) [b](irc://x/y)\n") as home:
      out = self._render(f'<!-- [include:{home}/page.md] -->\n')
    assert 'href="tel:+15551212"' in out
    assert 'href="irc://x/y"' in out

  def test_a_link_naming_no_file_is_refused(self) -> None:
    import pytest

    # A wrong-case link is refused either as missing or as misspelt, by
    # the case rules of the host the tests run on.
    cases = (
      ("[a](./nope.md)", "no such file"),
      ("[a](../README.MD)", r"no such file|not spelt"),
    )
    for source, message in cases:
      with self._scratch(page=f"{source}\n") as home:
        with pytest.raises(ValueError, match=message):
          self._render(f'<!-- [include:{home}/page.md] -->\n')

  @staticmethod
  def _pointer() -> IncludePreprocessor:
    import markdown

    return IncludePreprocessor(markdown.Markdown(), _REPO, _BRANCH)

  def test_address_collapses_the_stems_zensical_indexes(self) -> None:
    at = self._pointer()
    for stem in ("README", "index"):
      assert at._address(_DOCS_ROOT / "kit" / f"{stem}.md") == "/kit/"

  def test_address_keeps_the_stems_zensical_serves_as_pages(self) -> None:
    at = self._pointer()
    assert at._address(_DOCS_ROOT / "kit" / "readme.md") == "/kit/readme/"
    assert at._address(_DOCS_ROOT / "kit" / "Index.md") == "/kit/Index/"
    assert at._address(_DOCS_ROOT / "kit" / "guide.md") == "/kit/guide/"

  def test_spelling_check_matches_the_stored_name(self) -> None:
    root = root_dir()
    assert spelt_as_stored(root, root / "README.md")
    assert not spelt_as_stored(root, root / "README.MD")
    assert not spelt_as_stored(root, root / "Docs" / "README.md")

  def test_include_survives_a_fenced_info_string(self) -> None:
    out = self._render(
      '```text\n```markdown\n<!-- [include:maint/commit.toml] -->\n```\n'
    )
    assert "[include:maint/commit.toml]" in out
    assert "[default]" not in out

  def test_alert_survives_a_fenced_info_string(self) -> None:
    out = self._render("```\n```text\n> [!NOTE]\n> Shown.\n```\n")
    assert "[!NOTE]" in out
    assert "admonition" not in out

  def test_site_root_link_is_left_for_postprocessing(self) -> None:
    with self._scratch(page="[a](/dev/about_docs/)\n") as home:
      out = self._render(f'<!-- [include:{home}/page.md] -->\n')
    assert 'href="/dev/about_docs/"' in out

  def test_a_fence_an_include_opens_holds_over_the_parent(self) -> None:
    with self._scratch(opener="```text\n", body="spliced text\n") as home:
      out = self._pointer().run([
        f'<!-- [include:{home}/opener.md] -->',
        f'<!-- [include:{home}/body.md] -->',
        "```",
        f'<!-- [include:{home}/body.md] -->',
      ])
    # Held back while the literal fence the first splice opened is still
    # open, then spliced once the parent's own marker closes that fence.
    assert out[0] == "```text"
    assert out[1].startswith("<!-- [include:")
    assert out[2] == "```"
    assert out[3] == "spliced text"

  def test_fences_ignore_a_marker_carrying_text(self) -> None:
    fences = _Fences()
    assert fences.covers("```")
    assert fences.covers("```text")
    assert fences.covers("still inside")
    assert fences.covers("```")
    assert not fences.covers("outside")

  def test_fences_close_only_on_a_matching_marker(self) -> None:
    fences = _Fences()
    assert fences.covers("````")
    assert fences.covers("```")
    assert fences.covers("plain text")
    assert fences.covers("````")
    assert not fences.covers("plain text")
