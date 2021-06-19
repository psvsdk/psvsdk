# NAME

psv-vpk - Generate a Vita PacKage

# SYNOPSIS

    psv-vpk [HOST_PATH[:VPK_PATH]]... > out.vpk

# OPTIONS

  - HOST_PATH: path on the host filesystem (file or folder)
  - VPK_PATH:  path inside the package (HOST_PATH if no given)

# EXAMPLES

    psv-vpk app.sfo:sce_sys/param.sfo app.self:eboot.bin

# NOTES

Generated archive won't have CRCs (unused by the installer)
This can be seen as an issue from regular archive manager.
You can still extract them using: `unzip -od. no-crc.vpk`

# SEE ALSO
  - vpk(5)
