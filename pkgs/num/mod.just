# Recipes for dash-num, run as `just num::<recipe>`

import '../../bazel/mod.just'

# Build dash-num with cargo
build *flags='--features full':
    cargo build -p dash-num {{ flags }}

# Build dash-num with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/num/...
