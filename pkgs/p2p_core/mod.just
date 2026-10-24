# Recipes for dash-p2p-core, run as `just p2p_core::<recipe>`

import '../../bazel/mod.just'

# Build dash-p2p-core with cargo
build *flags='--features full':
    cargo build -p dash-p2p-core {{ flags }}

# Build dash-p2p-core with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/p2p_core/...
