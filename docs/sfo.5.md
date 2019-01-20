# NAME
sfo - System File Object

# DESCRIPTION
SFO files describe app metadata information to the VSH.
Some informations are displayed (TITLE) while others
are used by the VSH internally to load the app (CATEGORY...)

# FORMAT
SFO start with a HEADER section that refrence the N following entries,key,value sections
The following SFO dump example shall demonstrate how those section are related:

  HEADER
    0x00: 00 50 53 46 - magic       (\0PSF)
    0x04: 01 01 00 00 - version     (1.1)
    0x08: 24 00 00 00 - keys_off    (0x24) -------------------+
    0x0C: 30 00 00 00 - vals_off    (0x30) -------------------|-+
    0x10: 01 00 00 00 - entry_count (1)                       | |
  ENTRIES(0-N)                                                | |
    0x14: 00 00       - entry key offset (keys_off relativ)   | |
    0x16: 04          - entry (key?) alignment                | |
    0x17: 02          - entry type (0:?, 2:UTF-8, 4:uint32)   | |
    0x18: 0A 00 00 00 - entry val size (10 for BLUS12345\\0)   | |
    0x1C: 0F 00 00 00 - entry val limit (see wiki)            | |
    0x20: 00 00 00 00 - entry val offset (vals_off relativ)   | |
    [...]                                                     | |
  KEYS(0-N) <-------------------------------------------------+ |
    0x24: TITLE_ID\\0  - Notice the end delimiter                |
    [...]                                                       |
  PADDING             - 4 Bytes alignment                       |
    0x2D: 00 00 00    - 3 in our case                           |
  VALS(0-N) <---------------------------------------------------+
    0x30: BLUS12345\0 - size = 10, offset = 0
    [...]
# NOTE
 String attribut (eg. STITLE,TITLE) can use some emojis:
   ★☒☀☁☂☃☆☉☎☜☝☞☟♀♂♨♩♪♫♬♭♮♯
# SEE ALSO
  - <sfo.h>
  - https://vitadevwiki.com/vita/SFO
  - http://www.psdevwiki.com/ps4/Param.sfo
  - http://www.psdevwiki.com/ps3/PARAM.SFO
