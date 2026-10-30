# Recipes for dash-primitives, run as `just primitives::<recipe>`

import '../../bazel/mod.just'

# Build dash-primitives with cargo
build *flags='--features full':
    cargo build -p dash-primitives {{ flags }}

# Build dash-primitives with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/primitives/...
