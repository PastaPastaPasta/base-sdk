# Development shell for continuous integration

{
  commonTargets,
  compose,
  crossTargets,
  cxx,
  mods,
  ...
}:

compose [
  (cxx.forTargets crossTargets)
  (cxx.forWasm commonTargets)
  mods.bazel
  mods.codeql
  mods.cxx
  mods.fhs
  mods.nixpkgs
  mods.python
  mods.rust
]
