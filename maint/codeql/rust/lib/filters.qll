/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Common predicates for filtering types by context.
 */

import lib.ast
import rust

/** Materialises function spans per file for containment checks. */
pragma[nomagic]
private predicate functionSpan(File file, int fStart, int fEnd) {
  exists(Function f | file = fileOf(f) and fStart = startLine(f) and fEnd = endLine(f))
}

/** Holds if `t` is defined inside a function body rather than at module level. */
private predicate isLocalType(TypeItem t) {
  exists(File file, int fStart, int fEnd |
    functionSpan(file, fStart, fEnd) and
    file = fileOf(t) and
    startLine(t) > fStart and
    endLine(t) <= fEnd
  )
}

/** Materialises test module spans per file. */
pragma[nomagic]
private predicate testModuleSpan(File file, int mStart, int mEnd) {
  exists(Module m |
    file = fileOf(m) and
    mStart = startLine(m) and
    mEnd = endLine(m) and
    nameOf(m) = "tests" and
    m.getAnAttr().getMeta() instanceof CfgMeta
  )
}

/** Holds if `t` is inside a test module, test file, or benchmark. */
predicate isTestCode(Locatable t) {
  fileOf(t).getAbsolutePath().matches(["%/tests/%", "%/bench/%"])
  or
  exists(File file, int mStart, int mEnd |
    testModuleSpan(file, mStart, mEnd) and
    file = fileOf(t) and
    startLine(t) > mStart and
    endLine(t) <= mEnd
  )
}

/**
 * Holds if `t` has a derive attribute but no expansions, indicating
 * the extractor could not semantically process the containing file.
 */
predicate hasUnexpandedDerive(TypeItem t) {
  exists(Attr a |
    a = t.getAnAttr() and
    pathName(a.getMeta().getMetaPath()) = "derive"
  ) and
  not exists(t.getADeriveMacroExpansion())
}

/** Holds if `t` is defined in a build script. */
private predicate isBuildScript(TypeItem t) { fileOf(t).getAbsolutePath().matches("%/build.rs") }

/** Holds if `t` is a source type eligible for any check. */
predicate isSourceType(TypeItem t) {
  (t instanceof Struct or t instanceof Enum or t instanceof Union) and
  fileOf(t).fromSource() and
  not isBuildScript(t) and
  not isLocalType(t) and
  not isMacroGenerated(t) and
  not isTestCode(t)
}

/** Holds if struct `s` has exactly one unnamed (tuple) field. */
predicate isSingleTupleField(Struct s) { count(s.getFieldList().(TupleFieldList).getField(_)) = 1 }

/** Holds if `t` has a lifetime parameter in its generic params. */
predicate hasLifetime(TypeItem t) {
  exists(t.getGenericParamList().getAGenericParam().(LifetimeParam))
}

/** Gets the crate directory prefix for a source type. */
string cratePrefix(TypeItem t) {
  exists(string path |
    path = fileOf(t).getAbsolutePath() and
    result = path.regexpCapture("(.*/(?:meta|pkgs)/[^/]+/).*", 1)
  )
}

/** Gets the type name of a field in type item `t` (struct, enum, or union). */
string typeFieldName(TypeItem t) { result = typeHead(fieldTypeRepr(t)) }
