/**
# NAME
  psv-sfo - Generate a System File Object

# SYNOPSIS
  psv-sfo [KEY=STR | KEY=+INT]... > out.sfo
    Generate a SFO with the given KEY=VAL tuples

  psv-sfo < in.sfo
    Dump given in.sfo

  psv-sfo
    Show the help screen

# EXAMPLES
  Generate a default SFO
    psv-sfo > param.sfo

  Dump a SFO file
    psv-sfo < param.sfo

  Dump the default generated SFO on the fly
    psv-sfo < param.sfo

  Generate a SFO some string anf integer values (notice the +)
    psv-sfo STITLE=MyGame ATTRIBUTE=+0xFF > param.sfo

  psv-sfo | psv-sfo # generate a default sfo then dump it
# SEE ALSO
  - sfo(5)
*/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sfo.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#define countof(array) (sizeof(array) / sizeof(*(array)))
#define USAGE \
	"Usage: %s [ENTRY]... > out.sfo\n\n\
ENTRY\n	KEY=VAL_STR\n	KEY=+VAL_INT\n\n\
EXAMPLES\n	TITLE=ABC123\n	ATTRIBUTE=+0xFF\n"

#define MAX_SFO_ENTRY 32

/* Non Mandatory PSV SFO entries:
  {"ATTRIBUTE", 0x00000000},
  {"ATTRIBUTE2", 0x00000000},
  {"ATTRIBUTE_MINOR", 0x00000010},
  {"BOOT_FILE", 32, ""},
  {"CONTENT_ID", 48, ""},
  {"EBOOT_APP_MEMSIZE", 0x00000000},
  {"EBOOT_ATTRIBUTE", 0x00000000},
  {"EBOOT_PHY_MEMSIZE", 0x00000000},
  {"LAREA_TYPE", 0x00000000},
  {"NP_COMMUNICATION_ID", 16, ""},
  {"PARENTAL_LEVEL", 0x00000000},
  {"PSP2_DISP_VER", 8, "00.000"},
  {"TITLE", 0x80, ""},
  {"VERSION", 8, "00.00"},
*/

psv_entry_t mandatory_entries[] = {
 {"STITLE", 6, "SUPER"},
 {"TITLE_ID", 10, "ABCD99999"},
 {"APP_VER", 6, "01.00"},
 {"CATEGORY", 3, "gd"},
 {"PSP2_SYSTEM_VER", 0x00000000},
};

static ssize_t emiter(void* fd, const void* buf, size_t len) { return write(*(int*)fd, buf, len); }

static psv_entry_t* entry_find(psv_entry_t* entries, const char* key) {
	for (psv_entry_t* e = entries; e->key; e++)
		if (!strcmp(e->key, key))
			return e;
	return NULL;
}

int main(int argc, char** argv) {
	EXPECT(!isatty(STDOUT_FILENO) || !isatty(STDIN_FILENO), USAGE, argv[0]);

	if (!isatty(STDIN_FILENO)) {
		return psv_sfo_dump(STDIN_FILENO, STDOUT_FILENO);
	}
	/* Create and pre-fill our entries with mandatory psv_entries */
	psv_entry_t entries[MAX_SFO_ENTRY] = {};
	memcpy(entries, mandatory_entries, sizeof(mandatory_entries));
	psv_entry_t* last_entry = entries + countof(mandatory_entries);

	/* add/update psv entries from given argv */
	for (char *value, **arg = argv + 1; arg < argv + argc; arg++) {
		EXPECT(value = strchr(*arg, '='), "no value given for %s", *arg);
		*value++ = 0;
		/* locate existing entry, or locate a free slot (last_entry) */
		psv_entry_t* entry = entry_find(entries, *arg) ?: last_entry++;
		EXPECT(entry <= entries + countof(entries), "No more space for \"%s\"", *arg)
		if (value[0] == '+' || value[0] == '-') {
			*entry = (psv_entry_t){*arg, (uint32_t)(strtoul(value, NULL, 0))};
		} else {
			*entry = (psv_entry_t){*arg, (uint32_t)(strlen(value) + 1), value};
		}
	}

	psv_sfo_emit(entries, last_entry, emiter, &(int[]){STDOUT_FILENO});
	return 0;
}