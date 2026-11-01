# Fuzzing recipes, run as `just fuzz::<recipe>`

python := if os() == "windows" { "python" } else { "python3" }
ramdisk := if os() == "macos" { "/Volumes/mrd-fuzz" } else { "/mnt/mrd-fuzz" }
ramdisk_gib := env("FUZZ_RAMDISK_GIB", "8")
# `cargo afl` sets `RUSTFLAGS`, so `.cargo/config.toml` no longer applies.
# `rustflags` restates the platform minimum over the `target-cpu=native`
# that `cargo afl` adds.
x86_64_flags := "-C target-cpu=x86-64-v3 -C target-feature=+aes"
aarch64_flags := "-C target-cpu=generic -C target-feature=+aes"
rustflags := if arch() == "x86_64" { x86_64_flags } else if arch() == "aarch64" { aarch64_flags } else { "" }

import "pow/mod.just"

# AFL++ needs `cargo afl system-config` again after every reboot.
# Fetch sphlib, install cargo-afl and build AFL++
setup:
    git submodule update --init pow/sphlib
    cargo install --locked cargo-afl@0.18.2
    cargo afl config --build

# Check every stage against sphlib, natively and as a baseline `portable` build
test:
    git submodule update --init pow/sphlib
    cargo test --locked --workspace
    RUSTFLAGS="" cargo test --locked --workspace --features dash-pow/portable

# Reduce the queues of `target` under each of `roots` into its committed corpus
[private]
reduce-from crate target +roots:
    {{ python }} ../contrib/reduce_corpora.py --corpus {{ crate }}/corpora/{{ target }} \
      {{ prepend("--output ", append("/out/" + target, roots)) }} \
      {{ prepend("--binary ", append("/target/release/" + target, roots)) }}

# Build `target` of `dash-<crate>-fuzz` for AFL++ in a ramdisk
[private]
build crate target flags features root: mount-ramdisk
    RUSTFLAGS="{{ flags }}" CARGO_TARGET_DIR={{ root }}/target \
      cargo afl build --release -p dash-{{ crate }}-fuzz --bin {{ target }} {{ features }}

# Fuzz `target` of `dash-<crate>-fuzz` with AFL++ in a ramdisk
[private]
run crate target flags features root *args: (build crate target flags features root)
    mkdir -p {{ root }}/out
    AFL_AUTORESUME=1 cargo afl fuzz -i {{ crate }}/corpora/{{ target }} -o {{ root }}/out/{{ target }} \
      -x dicts/byte_patterns.dict {{ args }} \
      -- {{ root }}/target/release/{{ target }}

[private]
ramdisk *args:
    sudo "$(command -v {{ python }})" ../contrib/manage_ramdisk.py {{ args }}

[private]
mount-ramdisk:
    sudo "$(command -v {{ python }})" ../contrib/manage_ramdisk.py create --label fuzz --size {{ ramdisk_gib }}G --exist-ok
