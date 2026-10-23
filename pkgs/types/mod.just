# Recipes for dash-types and its marker macro, run as `just types::<recipe>`

import '../../bazel/mod.just'

# Build dash-types with cargo
build *flags='--features full':
    cargo build -p dash-types {{ flags }}

# Build dash-types with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/types/...
