# Development Shells

<!-- [include:contrib/nix/README.md:header] -->

> [!TIP]
> Should you wish to utilize devshells without installing Nix on your host, the environment is also available wrapped in
> a Docker [container](#docker); though it is still recommended to set up Nix for long-term development due to the cost
> associated with maintaining a parallel Nix store.

<!-- [include:contrib/nix/README.md:body] -->

<!-- pyml disable-next-line heading-increment -->
### Quirks

<!-- pyml disable-num-lines 27 no-emphasis-as-heading -->
* **The Python environment is read-only**

  Development shells (devshells) are immutable, this extends to packages sourced from PyPI. `uv` will neither sync nor
  install packages outside the initially defined set. To modify packages, edit [`pyproject.toml`](../../pyproject.toml),
  then generate an updated lockfile by running `uv lock` in the shell. Then re-enter a fresh devshell, it should take on
  the new definitions.

* **Linux devshells expect a standard layout**

  Binaries built for standard Linux systems look for dynamic loaders and libraries at paths NixOS leaves empty.
  `fhs-run <command>` runs a command in an [FHS](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html) layout
  typical of Linux distributions, and `fhs-run bash` opens a shell in it. The Docker container enters it by default.

* **Pinned versions of tools don't match against manual setup**

  Manual setup installs PyPI-sourced dependencies with `.dev`. Not every PyPI package is written in Python nor does it
  have to expose a Pythonic API to qualify for publication on PyPI. This allows PyPI to serve as a general means to
  distribute binaries so long as they otherwise meet PyPI's guidelines.

  This makes PyPI serve as a parallel package source and `.dev` leverages this to have better control over dependencies
  instead of relying on platform-specific package sources. We do not do this in devshells, preferring `nixpkgs` when
  feasible (and falling back on PyPI when it isn't, segmenting these packages as `.lib` in
  [`pyproject.toml`](../../pyproject.toml)). This leads to predictable drift between the versions pinned in
  [`uv.lock`](../../uv.lock) and versions published in the pinned snapshot of `nixpkgs` in
  [`flake.lock`](../../contrib/nix/flake.lock).

  This drift is benign. Should there be any difference in outcome, consider
  [filing an issue](https://github.com/dashpay/base-sdk/issues/new).

<!-- [include:contrib/docker/README.md] -->

<!-- pyml disable-next-line heading-increment,no-duplicate-heading -->
### Quirks

<!-- pyml disable-num-lines 27 no-emphasis-as-heading -->
* **`nix_shell` doesn't work standalone**

  `nix_shell` intentionally does not host the daemon, instead, delegating that to a dedicated `nix_daemon` container.
  This is to avoid churn and to achieve better isolation. Nix stores are expensive in storage cost (and initially for
  built elements, compute), so the interactive container talks to the store-hosting container, permitting flexible
  setups where multiple containers can leverage the same underlying store.

  Managing the containers _outside_ Docker Compose is unsupported.
