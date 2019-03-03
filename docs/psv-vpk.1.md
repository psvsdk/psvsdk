# NAME
  psv-vpk - Generate a Vita PacKage

# SYNOPSIS
	psv-vpk [HOST_PATH[:VPK_PATH]]... [<in.self] >out.vpk

# OPTIONS
 - HOST_PATH: path on the host filesystem (file or folder)
 - VPK_PATH:  path inside the package (HOST_PATH if no given)

# EXAMPLES

	psv-vpk < a.self
	psv-vpk sce_sys assets:data a.self:eboot.bin
	psv-vpk <(psv-sfo TITLE="Hello World" ...):sce_sys/param.sfo < a.self

# NOTES

  Archived files will have they CRC field unset (because unchecked during unpacking)
  To extract VPK simply unzip it using: `unzip -od. *.vpk` (ignore bad CRC warning)

# SEE ALSO
  - vpk(5)
