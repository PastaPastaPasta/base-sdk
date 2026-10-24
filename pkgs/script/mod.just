# Recipes for dash-script, run as `just script::<recipe>`

import '../../bazel/mod.just'

# Build dash-script with cargo
build *flags='--features full':
    cargo build -p dash-script {{ flags }}

# Build dash-script with Bazel
zbuild *flags:
    bazel build {{ flags }} //pkgs/script/...
