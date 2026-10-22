# Bazel settings shared by the root and crate justfiles.

# Read by bazelisk, which otherwise downloads Bazel into the user's cache.
export BAZELISK_HOME := justfile_directory() + "/.cache/bazelisk"
