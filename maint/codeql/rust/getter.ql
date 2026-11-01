/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/getter-rules
 * @name Struct field access rules
 * @description Enforces private fields read through getters on structs.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags maintainability
 */

import lib.crates
import lib.filters
import lib.fmt
import lib.policy
import lib.traits
import rust

/**
 * Holds if a constructor macro declares `s`. `isSourceType` drops macro output,
 * but `impl_new!` and the `@no_new` arm of `codec_payload!` pass a source
 * struct through. `codec_base!` and `codec_type!` match by nesting `impl_new!`.
 */
private predicate isConstructorStruct(Struct s) {
  exists(MacroCall mc, MacroItems m |
    m.getItem(_) = s and
    mc.getMacroCallExpansion() = m and
    pathName(mc.getPath()) = ["impl_new", "codec_payload"]
  )
}

/**
 * Holds if `s` is a public struct in a `getter` crate. Unencodable structs
 * count too, since a public field on a signed payload bypasses its signature
 * setter. Iterators keep cursor state that callers have no use reading.
 */
predicate isGetterStruct(Struct s) {
  isGetterCrate(fileOf(s)) and
  isBarePublic(s.getVisibility()) and
  not isIteratorType(s) and
  fileOf(s).fromSource() and
  not isTestCode(s) and
  not isSerdeInternalType(s) and
  (isSourceType(s) or isConstructorStruct(s))
}

/**
 * Holds if an inherent impl of `s` defines `name` as a getter, a public method
 * taking only `self` and returning a value. Derived `getset` getters expand
 * into such impls.
 */
bindingset[name]
private predicate hasGetterMethod(Struct s, string name) {
  exists(Impl i, Function f |
    i.getSelf() = s and
    not exists(i.getTraitTy()) and
    not isTestCode(i) and
    f = implItem(i) and
    nameOf(f) = name and
    isBarePublic(f.getVisibility()) and
    exists(f.getRetType().getTypeRepr()) and
    exists(f.getParamList().getSelfParam()) and
    not exists(f.getParamList().getParam(_))
  )
}

/** Holds if the named field `f` of `s` is read through a getter. */
predicate hasGetter(Struct s, StructField f) {
  f = s.getFieldList().(StructFieldList).getAField() and
  hasGetterMethod(s, f.getName().getText())
}

/** Gets a field of `s`, named or positional. */
private AstNode structField(Struct s) {
  result = s.getFieldList().(StructFieldList).getAField() or
  result = s.getFieldList().(TupleFieldList).getField(_)
}

/** Gets the label of field `f` of `s`, its name or its position. */
private string fieldLabel(Struct s, AstNode f) {
  f = s.getFieldList().(StructFieldList).getAField() and
  result = f.(StructField).getName().getText()
  or
  exists(int i | f = s.getFieldList().(TupleFieldList).getField(i) | result = i.toString())
}

from AstNode field, string message
where
  exists(Struct s | isGetterStruct(s) and field = structField(s) |
    exists([field.(StructField).getVisibility(), field.(TupleField).getVisibility()]) and
    message = fmt("field {0} of {1} is visible, make it private", fieldLabel(s, field), nameOf(s))
    or
    not exists(field.(StructField).getVisibility()) and
    not hasGetter(s, field) and
    field instanceof StructField and
    message = fmt("field {0} of {1} has no getter", fieldLabel(s, field), nameOf(s))
  )
select field, message
