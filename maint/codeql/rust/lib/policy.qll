/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Rule-specific policy predicates for type classification.
 */

import lib.ast
import lib.crates
import lib.filters
import lib.source_lines
import lib.traits
import rust

/** Holds if `t` carries `#[derive(...name...)]` detected via source-line scanning. */
bindingset[name]
predicate hasDerive(TypeItem t, string name) {
  exists(Attr a, int srcLine, string relPath, string content |
    a = t.getAnAttr() and
    (
      a.getMeta().getMetaPath().getText() = "derive" or
      a.getMeta() instanceof CfgAttrMeta
    ) and
    fileRelPath(fileOf(t), relPath) and
    sourceLineContent(relPath, srcLine, content) and
    content.regexpMatch(".*\\b" + name + "\\b.*") and
    lineWithin(srcLine, a)
  )
}

/**
 * Holds if `t` implements `name`, through an impl the extractor saw or a
 * derive read from source.
 */
bindingset[name]
predicate hasTrait(TypeItem t, string name) { implementsTrait(t, name) or hasDerive(t, name) }

/** Holds if `t` is a non-wire type (Unencodable derive, or has __CodecMarker w/o Hashable). */
predicate isNotEncodable(TypeItem t) {
  hasDerive(t, "Unencodable")
  or
  implementsTrait(t, "__CodecMarker") and
  not implementsTrait(t, "Hashable")
}

/** Holds if `t` holds secret or security-sensitive material. */
predicate isSecretType(TypeItem t) {
  (
    nameOf(t).regexpMatch(".*(Secret|Private|Seed|Password|Mnemonic|SkBytes|DhBytes).*")
    or
    // "Share" is the one keyword that "Shared" (e.g. SharedState) matches without holding a secret,
    // so the guard applies to it alone, exceptions to this rule are explicitly enumerated.
    nameOf(t).regexpMatch(".*Share.*") and
    not nameOf(t).regexpMatch(".*Shared.*")
    or
    // Scalar field wrapper holding secret key material
    nameOf(t) = "Fr"
  ) and
  not nameOf(t) =
    [
      // A share *of a signature* is published, so it's non-secret. Excluded by exact name because
      // `BlsSkShare` and `RawShare` match the same Share substring and do carry secret scalars.
      "BlsSigShare",
      // A share *of a public key* is the point the quorum publishes for a participant, and what it
      // recovers to is the master key, which is also public.
      "BlsPkShare",
      // The identifier a share is issued against is the participant's, known to every member of the
      // quorum; only the scalar the share carries is secret.
      "BlsShareId",
      // A masternode's owner payouts and the shares of its collateral hold public scripts, key ids
      // and amounts.
      "PayoutShare",
      "CollateralShare",
      // Serde artifact to deserialize a tagged enum.
      "__Seed"
    ]
}

/** Holds if `t` is an iterator type (name ends with Iterator or Iter). */
predicate isIteratorType(TypeItem t) {
  nameOf(t).matches("%Iterator") or
  nameOf(t).matches("%Iter")
}

/** Holds if `t` is an error type (name ends with Error, Invalid, TooLong, or TooShort). */
predicate isErrorType(TypeItem t) {
  nameOf(t).matches("%Error") or
  nameOf(t).matches("%Invalid") or
  nameOf(t).matches("%TooLong") or
  nameOf(t).matches("%TooShort")
}

/** Holds if `t` is a dispatch/message type (name ends with Message). */
private predicate isDispatchType(TypeItem t) { nameOf(t).matches("%Message") }

/** Holds if `t` is an opaque single-field wrapper. */
private predicate isOpaqueType(TypeItem t) {
  t instanceof Struct and
  isOpaqueCrate(fileOf(t)) and
  isSingleTupleField(t)
}

/** Holds if `t` is a compile-time marker type (empty enum, zero-sized). */
private predicate isMarkerType(TypeItem t) {
  t instanceof Enum and
  t.(Enum).hasVariantList() and
  count(t.(Enum).getVariantList().getAVariant()) = 0
}

/** Materialises (TypeItem, fieldTypeName, crate) for join efficiency. */
pragma[nomagic]
private predicate fieldTypeInCrate(TypeItem t, string fieldTypeName, string crate) {
  fieldTypeName = typeFieldName(t) and crate = cratePrefix(t)
}

/** Materialises (TypeItem, name, crate) for join efficiency. */
pragma[nomagic]
private predicate typeNameInCrate(TypeItem t, string name, string crate) {
  name = nameOf(t) and crate = cratePrefix(t)
}

/** Holds if struct `s` contains a float field, directly or transitively. */
private predicate hasFloatField(TypeItem t) {
  typeFieldName(t) = ["f32", "f64"]
  or
  exists(TypeItem inner, string name, string crate |
    fieldTypeInCrate(t, name, crate) and
    typeNameInCrate(inner, name, crate) and
    hasFloatField(inner)
  )
}

/**
 * Holds if `t` is a serde internal generated type
 * (e.g. __FieldVisitor, __Visitor, __Field).
 */
predicate isSerdeInternalType(TypeItem t) { nameOf(t).matches("\\_\\_%") }

/** Gets a required trait name. */
string requiredTrait() { result = ["Clone", "Debug", "Eq", "Hash", "PartialEq"] }

/** Gets a required serde trait name. */
string requiredSerdeTrait() { result = ["Serialize", "Deserialize"] }

/** Holds if `t` is codec infrastructure (decoder, encoder, or buffer types). */
private predicate isCodecType(TypeItem t) {
  nameOf(t).matches("%Decoder%") or
  nameOf(t).matches("%Encoder%") or
  nameOf(t) = "ArrayBuf"
}

/** Holds if `name` is a trait whose methods must have a body in exactly one layer. */
predicate isMutexTrait(string name) { name = "BlsScheme" }

/** Holds if `t` is a source type eligible for the "must derive" check. */
predicate isCheckableType(TypeItem t) {
  isSourceType(t) and
  not isSerdeInternalType(t) and
  not isCodecType(t) and
  not isSecretType(t) and
  not isIteratorType(t) and
  not isNoDeriveCrate(fileOf(t)) and
  not hasUnexpandedDerive(t)
}

/**
 * Holds if `t` implements a serde trait via crate-qualified impl,
 * unqualified proc-macro expansion, or source-scanned match.
 */
bindingset[traitName]
predicate implementsSerdeTrait(TypeItem t, string traitName) {
  implementsTraitInCrate(t, traitName, "serde")
  or
  // Serde proc-macro derives may emit unqualified impls that
  // escape MacroItems wrapping.  Detect them by requiring the
  // impl location to fall inside the type definition span (a
  // hand-written impl is always outside that span).
  (traitName = "Serialize" or traitName = "Deserialize") and
  exists(Impl i |
    not isMacroGenerated(i) and
    fileOf(i) = fileOf(t) and
    implSelfName(i) = nameOf(t) and
    implTraitName(i) = traitName and
    lineWithin(startLine(i), t)
  )
  or
  // Derive mention inside an attribute range (cfg_attr, cfg, or derive).
  exists(Attr a, int srcLine, string relPath, string content |
    a = t.getAnAttr() and
    fileRelPath(fileOf(t), relPath) and
    sourceLineContent(relPath, srcLine, content) and
    content.regexpMatch(".*\\b" + traitName + "\\b.*") and
    lineWithin(srcLine, a)
  )
  or
  // Manual impl behind #[cfg(feature = "serde")] that the
  // extractor cannot see.
  exists(string relPath, string content |
    fileRelPath(fileOf(t), relPath) and
    sourceLineContent(relPath, _, content) and
    content.regexpMatch("impl\\b.*\\bserde::" + traitName + "\\b.*\\bfor\\s+" + nameOf(t) + "\\b.*")
  )
}

/**
 * Holds when `trait` should not be required for `t`.
 */
predicate isSuppressed(TypeItem t, string trait) {
  // Float types: suppress Eq and Hash
  hasFloatField(t) and trait = ["Eq", "Hash"]
  or
  // Error types: suppress Hash
  isErrorType(t) and trait = "Hash"
  or
  // Dispatch types: suppress Hash
  isDispatchType(t) and trait = "Hash"
  or
  // Opaque types: suppress Hash
  isOpaqueType(t) and trait = "Hash"
  or
  // Projective point wrappers hold non-canonical coordinates: suppress Eq and PartialEq
  isOpaqueType(t) and
  nameOf(t) = ["G1", "G2"] and
  trait = ["Eq", "PartialEq"]
}

/** Holds if `t` is exempt from serde derivation requirements. */
predicate isSerdeExempt(TypeItem t) {
  isNonSerdeCrate(fileOf(t))
  or
  isNotEncodable(t)
  or
  isCodecType(t)
  or
  isErrorType(t)
  or
  isDispatchType(t)
  or
  isOpaqueType(t)
  or
  isMarkerType(t)
  or
  hasLifetime(t)
  or
  // Single-field wrappers without PartialEq are exempt.
  isSingleTupleField(t) and
  not implementsTrait(t, "PartialEq")
}

/** Declaration slots that define the required source ordering. */
private newtype TDeclSlot =
  TDefinition() or
  TNumericImpl() or
  TBaseCodecImpl() or
  TSignableImpl() or
  TCheckableImpl() or
  THashableImpl() or
  TInherentImpl() or
  TTraitImpl()

/** A declaration slot with ordering and labelling. */
class DeclSlot extends TDeclSlot {
  /** Gets the numeric ordering key for this slot. */
  int getOrder() {
    this = TDefinition() and result = 0
    or
    this = TNumericImpl() and result = 1
    or
    this = TBaseCodecImpl() and result = 2
    or
    this = TSignableImpl() and result = 3
    or
    this = TCheckableImpl() and result = 4
    or
    this = THashableImpl() and result = 5
    or
    this = TInherentImpl() and result = 6
    or
    this = TTraitImpl() and result = 7
  }

  /** Gets the human-readable label. */
  string toString() {
    this = TDefinition() and result = "definition"
    or
    this = TNumericImpl() and result = "Numeric impl"
    or
    this = TBaseCodecImpl() and
    result = "BaseCodec/Encode/Decode impl"
    or
    this = TSignableImpl() and result = "Signable impl"
    or
    this = TCheckableImpl() and result = "Checkable impl"
    or
    this = THashableImpl() and result = "Hashable impl"
    or
    this = TInherentImpl() and result = "inherent impl"
    or
    this = TTraitImpl() and result = "trait impl"
  }
}

/** Maps a trait name to its declaration slot. */
private DeclSlot traitSlot(string traitName) {
  traitName = "Numeric" and result = TNumericImpl()
  or
  traitName = "BaseCodec" and result = TBaseCodecImpl()
  or
  traitName = "Encode" and result = TBaseCodecImpl()
  or
  traitName = "Decode" and result = TBaseCodecImpl()
  or
  traitName = "Signable" and result = TSignableImpl()
  or
  traitName = "Checkable" and result = TCheckableImpl()
  or
  traitName = "Hashable" and result = THashableImpl()
}

/** Gets the slot for trait `trait`. */
bindingset[trait]
pragma[inline]
private DeclSlot traitImplSlot(string trait) {
  result = traitSlot(trait)
  or
  not exists(traitSlot(trait)) and result = TTraitImpl()
}

/**
 * Maps `(type, slot, line, loc)` for all definition-related items.
 *
 * Keyed by `TypeItem` to avoid conflating same-named types
 * in different modules within the same file.
 */
pragma[noinline]
predicate itemEntry(TypeItem t, DeclSlot slot, int line, Locatable loc) {
  isSourceType(t) and
  (t instanceof Struct or t instanceof Enum) and
  (
    // Definition.
    slot = TDefinition() and line = startLine(t) and loc = t
    or
    // Hand-written trait impls.
    exists(Impl i, string trait |
      manualTraitImpl(t, trait, i, line) and
      slot = traitImplSlot(trait) and
      loc = i
    )
    or
    // Macro-generated trait impls (e.g. impl_type!).
    exists(Impl i, string trait |
      macroTraitImpl(t, trait, i, line) and
      slot = traitImplSlot(trait) and
      loc = i
    )
    or
    // Inherent impl.
    exists(Impl i |
      inherentImpl(t, i, line) and
      slot = TInherentImpl() and
      loc = i
    )
  )
}
