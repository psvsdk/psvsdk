/**
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

	psv-sfo TITLE/128="TITLE" STITLE="hello world" TITLE_ID=ABCD99999 APP_VER=01.00 CATEGORY=gd PSP2_SYSTEM_VER=0x0 ATTRIBUTE=0x8000 > bare.sfo

  Remove the BOOT_FILE attribute from a base.sfo

	psv-sfo < base.sfo | grep -v BOOT_FILE | xargs psv-sfo > stripped.sfo

# ENVIRONMENT VARIABLES
  - VERBOSE (any value): print more details on stderr

# LIMITATIONS
  - psv-sfo allow multiple same KEYS, also multiple KEYS pointing to the same value (using manual offset)
  - psv-sfo can produce undefined output for (manually given) overlapping values or unordered KEY/VAL offset
  - `xargs` piping does not work natively because both psv-sfo invocation will have they stdin and stdout piped.
    In order to forward extracted values from `in.sfo` into the `out.sfo`, re-open stdin using `xargs -o`.
    This way, the second invocation will behave as if you called it with all the values as argv and no stdin pipes.
	psv-sfo < in.sfo | xargs -o psv-sfo > out.sfo # GOOD
	psv-sfo < in.sfo | xargs    psv-sfo > out.sfo # BAD

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
#ifndef USAGE
#define USAGE "See man psv-sfo\n"
#endif
#define MAX_SFO_ENTRY 32
#define MAX_SFO_KEY 32
#define MAX_SFO_VAL 128

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

/*
psv_entry_t mandatory_entries[] = {
 {"STITLE", 6, "SUPER"},
 {"TITLE_ID", 10, "ABCD99999"},
 {"APP_VER", 6, "01.00"},
 {"CATEGORY", 3, "gd"},
 {"PSP2_SYSTEM_VER", 0x00000000},
};
static psv_entry_t* entry_find(psv_entry_t* entries, const char* key) {
	for (psv_entry_t* e = entries; e->key; e++)
		if (!strcmp(e->key, key))
			return e;
	return NULL;
}
 */

static ssize_t emitter(void *fd, const void *buf, size_t len) { return write(*(int*)fd, buf, len); }
ssize_t psv_sfo_to_args(int in, int out) {
	sfo_header_t hdr;
	ssize_t ret, pos = read(in, &hdr, sizeof(hdr));
	sfo_entry_t entries[MAX_SFO_ENTRY];
	pos += read(in, &entries, sizeof(sfo_entry_t) * hdr.entry_count);

	for(uint8_t c; pos < MIN(hdr.keys_off, hdr.vals_off); pos += read(in, &c, sizeof(c)));
	bool keys_first = hdr.keys_off < hdr.vals_off;

	char keys_section[MAX_SFO_ENTRY * MAX_SFO_KEY];// 64 keys of 32 bytes
	char vals_section[MAX_SFO_ENTRY * MAX_SFO_VAL];// 64 values of 128 bytes

	if (keys_first) {
		EXPECT(hdr.vals_off - hdr.keys_off <= sizeof(keys_section), "too much keys");
		pos += read(in, &keys_section, hdr.vals_off - hdr.keys_off);
		pos += (ret = read(in, &vals_section, sizeof(vals_section)));
		if(ret == sizeof(vals_section))return -1;
	} else {
		EXPECT(hdr.keys_off - hdr.vals_off > sizeof(vals_section), "too much vals (%i %i < %zu)", hdr.keys_off, hdr.vals_off, sizeof(vals_section));
		pos += read(in, &vals_section, hdr.keys_off - hdr.vals_off);
		pos += (ret = read(in, &keys_section, sizeof(keys_section)));
		if(ret == sizeof(keys_section))return -1;
	}
	uint32_t expected_key = 0, expected_val = 0;
	for (sfo_entry_t*ent = entries; ent < entries+hdr.entry_count; ent++) {
		dprintf(out, "%s", keys_section + ent->key_off);
		char* val = vals_section + ent->val_off;
		if ((ent->type != PSF_TYPE_STR && ent->type != PSF_TYPE_U32) || // explicit type if neither STR nor U32
		    (ent->type == PSF_TYPE_STR && val[0]=='0' && (val[1]=='x' || val[1]=='X'))) { // or if is string and is 0x...
			dprintf(out, ":%i",ent->type);
		}
		if ((ent->type != PSF_TYPE_U32 || ent->val_length != 4) &&
		    (ent->type == PSF_TYPE_STR && ent->val_length != 1 + strlen(vals_section+ent->val_off))) {
			dprintf(out, "*%i", ent->val_length);
		}
		if ((ent->type == PSF_TYPE_U32 && ent->val_limit != 4) ||
		    (ent->type == PSF_TYPE_STR && ent->val_limit != ALIGN(ent->val_length-1))) {
			dprintf(out, "/%i", ent->val_limit);
		}
		if (ent->alignment != 4) {
			dprintf(out, "~%i", ent->alignment);
		}
		if (ent->key_off!= expected_key) {
			dprintf(out, "@%i", ent->key_off);
		}
		if (ent->val_off!= expected_val) {
			dprintf(out, "-%i", ent->val_off);
		}
		if (ent->type == PSF_TYPE_U32) {
			dprintf(out, "=0x%08X\n", *((uint32_t*)(vals_section+ent->val_off)));
		} else {
			dprintf(out, "=\"%.*s\"\n", ent->val_length, vals_section+ent->val_off); // TODO escape (& unescape) quotes ?
		}
		expected_key += strlen(keys_section + ent->key_off) + 1;
		expected_val += ent->val_limit;
	}
	// dprintf(out, "\n");
	return pos;
}

int psv_sfo_from_args(int argc, char **argv, char**keys, char**vals, sfo_entry_t*entries) {
	for (int i = 0 ; i < argc; i++) {
		sfo_entry_t* entry = &entries[i];

		char *val = strchr(argv[i] , '=');
		EXPECT(val, "no value given for %s", argv[i]);
		*val++ = 0;
		vals[i] = val;

		memset(entry, 0xFF, sizeof(*entry));
		for(char* k = keys[i] = argv[i]; *k; k++) {
			switch(*k) {
				case ':': entry->type      = (uint8_t)  strtoul(k + 1, NULL, 0); break;
				case '*': entry->val_length= (uint32_t) strtoul(k + 1, NULL, 0); break;
				case '/': entry->val_limit = (uint32_t) strtoul(k + 1, NULL, 0); break;
				case '~': entry->alignment = (uint8_t)  strtoul(k + 1, NULL, 0); break;
				case '@': entry->key_off   = (uint16_t) strtoul(k + 1, NULL, 0); break;
				case '-': entry->val_off   = (uint32_t) strtoul(k + 1, NULL, 0); break;
				default: continue;
			}
			*k = 0;
		}
		// setup defaults values if still undefined
		if (entry->alignment == 0xFF) {
			entry->alignment = 4;
		}
		if (entry->type == 0xFF) {
			entry->type = (uint8_t) (val[0] == '0' && val[1] == 'x' ? PSF_TYPE_U32 : PSF_TYPE_STR);
		}
		if (entry->type == 0xFF) {
			entry->type = (uint8_t) (val[0] == '0' && (val[1] == 'x') ? PSF_TYPE_U32 : PSF_TYPE_STR);
		}
		if (entry->val_length == 0xFFFFFFFF) {
			entry->val_length = (uint32_t) (entry->type == PSF_TYPE_U32 ? sizeof(uint32_t) : strlen(val) + 1);
		}
		if (entry->val_limit == 0xFFFFFFFF) {
			entry->val_limit = ALIGN(entry->val_length);
		}
		if (entry->key_off == 0xFFFF) {
			entry->key_off = (uint16_t) (i ? entries[i - 1].key_off + strlen(keys[i - 1]) + 1 : 0);
		}
		if (entry->val_off == 0xFFFFFFFF) {
			entry->val_off = i ? entries[i-1].val_off + entries[i-1].val_limit : 0;
		}
		
		if(getenv("VERBOSE")) {
			fprintf(stderr, "%s:%i*%i/%i~%i@%i-%i=\"%s\"\n", keys[i],
			        entry->type, entry->val_length, entry->val_limit, entry->alignment, entry->key_off, entry->val_off, vals[i]);
		}
	}
	return 0;
}

int main(int argc, char** argv) {
	if(getenv("VERBOSE")) {
		fprintf(stderr, "pipe<in:%i,out:%i>\n", !isatty(STDIN_FILENO), !isatty(STDOUT_FILENO));
	}

	// no in or out redirect => get help
	if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
		return fprintf(stderr, USAGE);
	}
	// input SFO => dump sfo as args
	if (!isatty(STDIN_FILENO)) {
		return psv_sfo_to_args(STDIN_FILENO, STDOUT_FILENO) > 0;
	}
	// output SFO requested
	if (!isatty(STDOUT_FILENO)) {
		sfo_entry_t entries[MAX_SFO_ENTRY] = {};
		char* keys[MAX_SFO_ENTRY] = {};
		char* vals[MAX_SFO_ENTRY] = {};
		argv++;argc--;
		EXPECT(argc < countof(entries), "Too much arguments");
		EXPECT(!psv_sfo_from_args(argc, argv, keys, vals, entries), "Unable to parse arguments");
		psv_sfo_emit(argc, keys, vals, entries, emitter, &(int[]) {STDOUT_FILENO});
		return 0;
	}
}
