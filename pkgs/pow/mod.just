# Recipes for dash-pow, run as `just pow::<recipe>`

import '../../bazel/mod.just'

# Build dash-pow with cargo
build *flags='--features full':
    cargo build -p dash-pow {{ flags }}

# Build dash-pow with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/pow/...
