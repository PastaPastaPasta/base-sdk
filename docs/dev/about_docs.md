# Documentation

This guide is generated using [Zensical](https://pypi.org/project/zensical/) (a fork of
[MkDocs](https://pypi.org/project/mkdocs/)), with additional [pre](#preprocessing)- and
[post](#postprocessing)-processing to make the source material render adequately on the forge provider, GitHub.

## Installing dependencies

> [!NOTE]
> If you haven't set up your development environment, check out the [startup guide](./getting_started.md) first.
> If you're in a [development shell](./devshells.md), `wasm-pack` is included and this step can be skipped.

The documentation comes bundled with web-ready demos, which are powered by WebAssembly. Preparing them for
distribution relies on [`wasm-pack`](https://github.com/wasm-bindgen/wasm-pack), which is installed as a binary crate.

```bash
cargo install wasm-pack
```

## Building

> [!WARNING]
> Due to a limitation in Zensical, the target bundle cannot be emitted in the usual `public/` directory.
> This is because a target path must be at or in a child directory relative to [`zensical.toml`](../zensical.toml).
> For more information, see [zensical/backlog#56](https://github.com/zensical/backlog/issues/56).

To generate the target bundle, run the following from the repository root. The target bundle will be located at
`docs/.site`.

```bash
python docs/build_docs.py build
```

### Preview

> [!TIP]
> If a preview appears stale even after rebuilding, you may need to clear `docs/.{cache,site}`.

To preview the site live, run the following from the repository root.

```bash
python docs/build_docs.py preview
```

Live reload is unsupported due to additional processing and compilation artifacts. Using `zensical` directly for
previews or builds may result in a broken site.

## Preprocessing

This documentation has two audiences, GitHub and Zensical. This created an impasse between two competing Markdown
extensions, [GitHub-flavoured Markdown](https://github.github.com/gfm/) (GFM) and
[Python-Markdown](https://pypi.org/project/Markdown/) syntax. Two measures resolve it.

* Naming base pages `README.md` instead of `index.md`, so that GitHub renders a directory's associated base page instead
  of returning empty.
* Processing Markdown files (see [`preprocess.py`](../preprocess.py)) through a Python-Markdown extension before it is
  rendered by Zensical as a webpage.

### Admonitions

The Python ecosystem settled on a syntax for [admonitions](https://zensical.org/docs/authoring/admonitions/) that can
then be extended by Zensical to offer arbitrary icons and accent colors with adequate theming. By contrast, GFM alerts
are relatively rigid but are broadly supported in the Markdown ecosystem (including by WYSIWYG editors like
[Typora](https://typora.io/)).

To bridge this gap, alerts are mapped to the nearest fitting admonition, `[!IMPORTANT]` becomes `info` and `[!CAUTION]`
becomes `danger`.

### Link processing

> [!TIP]
> To cite specific line (ranges), it is advised to link against a commit-pinned version of that file on GitHub (or
> elsewhere reachable on the open web) to ensure that the ranges don't turn stale as the codebase evolves.

On-disk link targets are written relative to the file defining it, as only files under `docs/` are carried into the
target bundle. To allow links outside `docs/` to resolve to a valid path, links pointing to valid on-disk elements
outside `docs/` resolve to the forge instead.

> [!WARNING]
> Zensical treats on-disk `.md` links as documentation and will fail to build if they are located outside `docs/`.
> This does not affect non-Markdown files and directories. [Omitted](#omitting) segments are not processed at all.

### Splicing

To keep material that would otherwise be duplicated from falling out of sync, a document can be split into reusable
segments that other documents splice in, or to assemble a document outright. This lets the on-disk layout keep
documentation close to the material it describes, while keeping the prose cohesive when it is read as a webpage.

Splicing happens when the site is built, so a document read on GitHub is the file as stored on-disk, without the
segments spliced in. We use a custom comment syntax to ensure that splice markers are invisible, so they don't interfere
with GitHub and WYSIWYG editors.

This makes Zensical the primary authority on the _shape_ of a document and it is recommended to [preview](#preview) your
edits and the pages that could be affected by your edits to ensure it remains pleasant to read.

To splice in a whole document, or a spliced segment of it (like `setup`), the syntax is as below.

```text
<!-- [include:contrib/README.md] -->
<!-- [include:contrib/README.md:setup] -->
```

> [!WARNING]
> `omit` is a reserved label for _stripping_ spliceable regions from the final document. See [Omitting](#omitting) for
> more details.

To create a spliceable segment, wrap the desired text in `start` and `end` markers carrying its label (like `setup`).

```text
<!-- [start:setup] -->
Carried into the splice.
<!-- [end:setup] -->
```

Links in spliced material are resolved against the file that defines them, not the page splicing it in (see
[link processing](#link-processing)). Splices may nest.

#### Inlining

> [!TIP]
> To write directives as literal text without parsing it, wrap the text segment in a code block with
> formatting type text (i.e. &#96;&#96;&#96;text). This will instruct the preprocessor to _not_ interpret the
> captured segment as directives, quoting or otherwise.

Example code has a recurring problem of staleness, where (especially in early incubation), code segments may undergo
radical changes in shape, scope and location. This can result in examples that at best, don't compile at all and at
worst, enact behaviors that do not match the text description or mislead the reader.

This is avoided by using segments from the live codebase, as shown below for inlining a complete file.

````text
```toml
<!-- [include:maint/commit.toml] -->
```
````

> [!WARNING]
> Splicing non-Markdown files outside code blocks is prohibited as Markdown files undergo additional processing steps
> and such files have a high tendency of disturbing the final page render.

And for partial inlining, the syntax is similar to regular splicing.

````text
# In Markdown

```rust
<!-- [include:pkgs/types/src/codec.rs:vec-codec] -->
```
````

With its counterpart in a source file appearing like so.

```rust
// In Rust

// [start:vec-codec]
impl<T: BaseCodec> Encoder for VecEncoder<T> {
  // ...
}
// [end:vec-codec]
```

### Omitting

Due to the dual-audience nature of our documentation, there may exist segments that are meant for GitHub but not
Zensical. The usual pattern for the reverse is to create a new file and then splice in what is required but this creates
situations where most of the file is included _except_ for a small portion. Omissions can take care of that.

To omit a segment, use the following syntax. Unlike other labels, `omit` can be used repeatedly but typos of `omit` will
be treated as ordinary spliceable segments.

```text
<!-- [start:omit] -->
Rendered on GitHub, absent from the site.
<!-- [end:omit] -->
```

## Postprocessing

> [!WARNING]
> The following is a workaround. Zensical does not offer a setting to hold a file back from the target bundle.
> Support for `not_in_nav` ([zensical/backlog#63](https://github.com/zensical/backlog/issues/63)) as well as
> `exclude_docs` and `draft_docs` ([zensical/backlog#65](https://github.com/zensical/backlog/issues/65)) is pending.

Zensical copies the whole of `docs/` into the target bundle, so sources, manifests, scripts and other non-publishable
materials are included in the target bundle and may end up exposed on the open web. To avoid this,
[`.zenignore`](../.zenignore) lists globs for elements to be excluded from the target bundle. **While `.zenignore` has
similar syntax to `.gitignore`, exclusions (`!`) are not supported and will result in a hard error.**
