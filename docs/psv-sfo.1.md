# NAME
  psv-sfo - Create/Dump/Edit a System File Object

# SYNOPSIS
	psv-sfo < dumped.sfo
	psv-sfo [OPTIONS]... > create.sfo
	psv-sfo < base.sfo | xargs -o psv-sfo [OPTIONS]... > extended.sfo
	psv-sfo < base.sfo | grep -v LAREA_TYPE | xargs -o psv-sfo > no_larea.sfo
	psv-sfo < base.sfo | grep -v LAREA_TYPE | xargs -o psv-sfo LAREA_TYPE=0x2 > replaced_larea.sfo

# OPTIONS
  each OPTION consist of a KEY=VALUE pair with possible tuning:

	KEY[:type][*size][/limit][~align][@keyoff][-valoff]=VALUE

  - `:type`   default to number (4) if value match the (0x...) pattern, string (2) otherwise
  - `*length` default to strlen(VAL)+1 for string (:2) and sizeof(u32) for number (:4)
  - `/limit`  default to CEIL(4, size)
  - `~align`  default to 4
  - `@keyoff` default to (prev_key.offset + strlen(prev_key) + 1)
  - `-valoff` default to (prev_val.offset + prev_val.limit)

# EXAMPLES:
  Build a Vita valid SFO:

	psv-sfo APP_VER=1.0 CATEGORY=gd PSP2_SYSTEM_VER=0x0 ATTRIBUTE=0x8000 \
	        TITLE/128="hello" STITLE="world" TITLE_ID=ABCD99999 > a.sfo

  Remove the BOOT_FILE attribute from a base.sfo

	psv-sfo < base.sfo | grep -v BOOT_FILE | xargs psv-sfo > stripped.sfo

# MANDATORY ENTRIES
	STITLE="Short title"
	TITLE_ID=ABCD99999
	APP_VER=01.00
	CATEGORY=gd
	PSP2_SYSTEM_VER 0x00000000

# OPTIONAL ENTRIES
	ATTRIBUTE=0x00000000
	ATTRIBUTE2=0x00000000
	ATTRIBUTE_MINOR=0x00000010
	BOOT_FILE=""
	CONTENT_ID="..."
	EBOOT_APP_MEMSIZE=0x00000000
	EBOOT_ATTRIBUTE=0x00000000
	EBOOT_PHY_MEMSIZE=0x00000000
	LAREA_TYPE=0x00000000
	NP_COMMUNICATION_ID="myId"
	PARENTAL_LEVEL=0x00000000
	PSP2_DISP_VER=00.000
	TITLE="full title"
	VERSION=00.00

# ENVIRONMENT VARIABLES
  - DEBUG (any value): print more details on stderr

# CAUTION
  - psv-sfo allow multiple same KEYS, also multiple KEYS pointing to the same value (using manual offset)
  - psv-sfo can produce undefined output for (manually given) overlapping values or unordered KEY/VAL offset
  - `xargs` piping does not work natively because both psv-sfo invocation will have they stdin and stdout piped.
    In order to forward extracted values from `in.sfo` into the `out.sfo`, re-open stdin using `xargs -o`.
    This way, the second invocation will behave as if you called it with all the values as argv and no stdin pipes.


	psv-sfo < in.sfo | xargs -o psv-sfo > out.sfo # GOOD
	psv-sfo < in.sfo | xargs    psv-sfo > out.sfo # BAD

# SEE ALSO
  - sfo(5)
