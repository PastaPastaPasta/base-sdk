# Recipes for dash-pkc, run as `just pkc::<recipe>`

import '../../bazel/mod.just'

# Build dash-pkc with cargo
build *flags='--features full':
    cargo build -p dash-pkc {{ flags }}

# Build dash-pkc with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/pkc/...
