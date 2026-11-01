# `dash-pow` fuzzing recipes, imported into `fuzz/mod.just`

# The `portable` build has its own software-optimised code paths, so it relies on
# the platform's baseline and fuzzes in a separate ramdisk tree.
x86_64_baseline := "-C target-cpu=x86-64"
aarch64_baseline := "-C target-cpu=generic"
baseline_flags := if arch() == "x86_64" { x86_64_baseline } else if arch() == "aarch64" { aarch64_baseline } else { "" }
portable_ramdisk := ramdisk / "portable"
portable_features := "--features dash-pow/portable"

# Fuzz a `dash-pow` `target` against sphlib; extra arguments go to `afl-fuzz`
pow target *args: (run "pow" target rustflags "" ramdisk args)

# Fuzz the baseline `portable` build of a `dash-pow` `target` against sphlib
pow_portable target *args: (run "pow" target baseline_flags portable_features portable_ramdisk args)

# Reduce both AFL++ queues of `target` into its corpus, keeping what either build needs
pow_reduce target: (build-native target) (build-portable target) (reduce-from "pow" target ramdisk portable_ramdisk)

[private]
build-native target: (build "pow" target rustflags "" ramdisk)

[private]
build-portable target: (build "pow" target baseline_flags portable_features portable_ramdisk)
