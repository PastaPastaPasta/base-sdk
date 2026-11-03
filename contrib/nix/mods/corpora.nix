# Build dependencies of the C++ programs that write test corpora

{ pkgs }:

{
  packages = [
    pkgs.boost
    pkgs.cmake
    pkgs.gmp
  ];
}
