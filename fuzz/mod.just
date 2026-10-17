# Fuzzing recipes, run as `just fuzz::<recipe>`

python := if os() == "windows" { "python" } else { "python3" }
ramdisk := if os() == "macos" { "/Volumes/mrd-fuzz" } else { "/mnt/mrd-fuzz" }
ramdisk_gib := env("FUZZ_RAMDISK_GIB", "8")

[private]
ramdisk *args:
    sudo "$(command -v {{ python }})" ../contrib/manage_ramdisk.py {{ args }}

[private]
mount-ramdisk:
    sudo "$(command -v {{ python }})" ../contrib/manage_ramdisk.py create --label fuzz --size {{ ramdisk_gib }}G --exist-ok
