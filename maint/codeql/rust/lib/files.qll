/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Location and file helpers.
 */

import rust

/** Gets the start line of `n`. */
pragma[inline]
int startLine(Locatable n) { result = n.getLocation().getStartLine() }

/** Gets the end line of `n`. */
pragma[inline]
int endLine(Locatable n) { result = n.getLocation().getEndLine() }

/**
 * Holds if `line` falls within the span of `outer`, inclusive of both ends.
 */
bindingset[line]
pragma[inline]
predicate lineWithin(int line, Locatable outer) {
  line >= startLine(outer) and
  line <= endLine(outer)
}

/** Gets the file containing `n`. */
pragma[inline]
File fileOf(Locatable n) { result = n.getLocation().getFile() }

/** Materialises the repo-root-relative path for source files. */
pragma[nomagic]
predicate fileRelPath(File f, string relPath) {
  relPath = f.getAbsolutePath().regexpCapture(".*/((?:meta|pkgs)/.*)", 1)
}

/** Holds if `f` belongs to a crate in this workspace. */
predicate isWorkspaceFile(File f) { fileRelPath(f, _) }
