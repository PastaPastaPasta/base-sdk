"""The Rust release every toolchain fetches, as rust-lang.org publishes it."""

# Every toolchain and the host tools use this stable release.
RUST_VERSION = "1.99.1"

# Digests from the `.sha256` sidecars at static.rust-lang.org/dist. A key
# missing here makes the fetch skip its integrity check, so every artifact a
# toolchain fetches must be listed.
RUST_SHA256S = {
    "cargo-1.99.1-aarch64-apple-darwin.tar.xz": "685e563d94db1f003ffa5f5831439eec02569b9950b69867953c8213269c1eaf",
    "clippy-1.99.1-aarch64-apple-darwin.tar.xz": "c463f31831196702fc544900a0dc4c1837905327507fbec751fe46e59ca098bf",
    "llvm-tools-1.99.1-aarch64-apple-darwin.tar.xz": "b348db9d79666aee4b5e2ff4269029fffd16815cbd47f47018cd0b06e4f815f5",
    "rust-std-1.99.1-aarch64-apple-darwin.tar.xz": "fe79d6ab5a0321de26463999d8c112b8ad3eafbcbcf822d66a2300b45dde1031",
    "rustc-1.99.1-aarch64-apple-darwin.tar.xz": "23948a0a9c162fd2952defb3fb0462c44e8fcfd1a4ab8a274a1e1bdb2cf810a3",
    "cargo-1.99.1-aarch64-unknown-linux-gnu.tar.xz": "5156832e0c1254e9b49a79edabdc6d4c35f32f8fc1cf3ca700f268ff96087ab0",
    "clippy-1.99.1-aarch64-unknown-linux-gnu.tar.xz": "3bea76c26dcf30c176c0a8a8cc283eb59fabd754e24a68b4ca0701e5f3245f6b",
    "llvm-tools-1.99.1-aarch64-unknown-linux-gnu.tar.xz": "cd1818058908c1c4e99bd2843fe103df255157454e16186ec9cc3b5b5823b39c",
    "rust-std-1.99.1-aarch64-unknown-linux-gnu.tar.xz": "e25668477083d6a9ddb87b9beb9c00742225f38233ccb4bfba3afa7a07427f52",
    "rustc-1.99.1-aarch64-unknown-linux-gnu.tar.xz": "acdcdfe09ae1f103aa9a2b7f88903a9588bc2e99288af10e6fbf5514e2e49f25",
    "cargo-1.99.1-x86_64-apple-darwin.tar.xz": "6636dabcec164909d1c6eb9e2c596148787c84f7d3a02ff68a141569077f80b5",
    "clippy-1.99.1-x86_64-apple-darwin.tar.xz": "b5810174b696eaa05dd4ffd5b24c40a33c6d4bccc05fb72264006b7bfefb8c5d",
    "llvm-tools-1.99.1-x86_64-apple-darwin.tar.xz": "3112e92b03b1cca4264a30ca602948d31976cd45db7de2bc7900efa25a39a045",
    "rust-std-1.99.1-x86_64-apple-darwin.tar.xz": "484d5b88b424ddd29df196e1eb9420c8335bb5fac90a3c37140253345a8c65c4",
    "rustc-1.99.1-x86_64-apple-darwin.tar.xz": "203feef2c2165d7dda1f30ccf75590f72a6abc52ce259ed1c418de84a6887698",
    "cargo-1.99.1-x86_64-unknown-linux-gnu.tar.xz": "53f3521949404d595efb06a55c12c5658d4ed1c75566f33d3d514eaebe70bd8a",
    "clippy-1.99.1-x86_64-unknown-linux-gnu.tar.xz": "458339712a058e52cc4522ff9ef8b59cd1ea1340312216cd94194c464a3f6dc5",
    "llvm-tools-1.99.1-x86_64-unknown-linux-gnu.tar.xz": "8429c5117debfb45c22cf2f97712ef00e0e94976c96cf92f661974a458ca7e84",
    "rust-std-1.99.1-x86_64-unknown-linux-gnu.tar.xz": "109b074225bf5b9ea3820890876bfdf4ed161adbfaf94b2b4b5984c85ee5d958",
    "rustc-1.99.1-x86_64-unknown-linux-gnu.tar.xz": "2ff05ff9c08a90861e7f6e4065b40a8b87463b4576186fd613871c3e37f2091f",
}

# rustc's default CPU for each triple. Naming it leaves codegen as it is but
# shows build scripts a `-Ctarget-cpu`, as `blst` needs one to pick a mode.
BASELINE_TARGET_CPUS = {
    "aarch64-apple-darwin": "apple-m1",
    "aarch64-unknown-linux-gnu": "generic",
    "x86_64-apple-darwin": "penryn",
    "x86_64-unknown-linux-gnu": "x86-64",
}
