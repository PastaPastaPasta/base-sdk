# Recipes for dash-params, run as `just params::<recipe>`

import '../../bazel/mod.just'

# Build dash-params with cargo
build *flags='--features full':
    cargo build -p dash-params {{ flags }}

# Build dash-params with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/params/...
