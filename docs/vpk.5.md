# NAME
vpk - Vita PacKage

# DESCRIPTION
Scene equivalent to Sonys PKGs
VPKs are ZIP files with at least a sce_sys/param.sfo file
and optionaly some specific media files in /sce_sys/
that will be be displayed on the livearea screen.

# FORMAT

  HEADER #0             <--+
   - type=VPK_LOCAL_HEADER |
   - magic                 |
   - flag                  |
   - method(0=uncompressed)|
   - mod_time              |
   - flags                 |
   - crc32 (not checked)   |
   - size_compressed       |
   - size_uncompressed     |
  FILE #0                  |
  ...
  HEADER #N             <--+
  FILE #N                  |
			   |
  DESCRIPTOR HEADER #0     |
   - offset                |
  ...                      |
  DESCRIPTOR HEADER #N     |
  CENTRAL DIRECTORY -------+
   - type=VPK_END_RECORD
   - total_files
   - total_size

# SEE ALSO
  - <vpk.h>
  - https://vitadevwiki.com/vita/VPK
  - https://en.wikipedia.org/wiki/Zip_(file_format)
