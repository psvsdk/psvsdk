/**
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
      0x18: 0A 00 00 00 - entry val size (10 for BLUS12345\\0)  | |
      0x1C: 0F 00 00 00 - entry val limit (see wiki)            | |
      0x20: 00 00 00 00 - entry val offset (vals_off relativ)   | |
      [...]                                                     | |
    KEYS(0-N) <-------------------------------------------------+ |
      0x24: TITLE_ID\\0  - Notice the end delimiter               |
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
*/

#ifndef SFO_H
#define SFO_H
#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PSF_MAGIC 0x46535000
#define PSF_VERSION 0x00000101
#define PSF_TYPE_STR 2u
#define PSF_TYPE_U32 4u
#define little __attribute__((packed, scalar_storage_order("little-endian")))
#define ALIGN(V) (((V) + ((4) - 1)) & ~((4) - 1))
#define MIN(A, B) (A < B ? A : B)

typedef struct little {
	uint32_t magic;
	uint32_t version;
	uint32_t keys_off;
	uint32_t vals_off;
	uint32_t entry_count;
} sfo_header_t;

typedef struct little {
	uint16_t key_off;
	uint8_t  alignment;
	uint8_t  type;
	uint32_t val_length;
	uint32_t val_limit;
	uint32_t val_off;
} sfo_entry_t;

typedef ssize_t (*sfo_emitter_t)(void* arg, const void* buf, size_t len);
/*
int psv_sfo_dump_key(int in, int out, sfo_header_t hdr, sfo_entry_t*entries) {
        uint8_t c;
        dprintf(out, "\n\n  KEY:");
        for (unsigned i = hdr.keys_off; i < hdr.vals_off && read(in, &c, sizeof(c)) > 0; i++) {
                for (unsigned e = 0; e < hdr.entry_count; e++) {
                        if (i == hdr.keys_off + entries[e].key_off) {
                                dprintf(out, "\n%5i: ", e);
                        }
                }
                dprintf(out, (c < ' ' || c > '~') ? "\\x%02X" : "%c%s", c, c=='\\'?"\\":"");
        }
}
int psv_sfo_dump_val(int in, int out, sfo_header_t hdr, sfo_entry_t*entries, unsigned val_section_size) {
        uint8_t c;
        dprintf(out, "\n\nVALUE:");
        sfo_entry_t* found_ent = NULL;
        for (unsigned i = 0; i < val_section_size && read(in, &c, sizeof(c)) > 0; i++) {
                for (unsigned e = 0; e < hdr.entry_count; e++) {
                        if (i == entries[e].val_off) {
                                found_ent = &entries[e];
                                dprintf(out, "\n%5i: %s", e, entries[e].type == 4 ? "0x" : "");
                        }
                }
                // if(found_ent && found_ent->val_length)
                dprintf(out, (found_ent && found_ent->type == PSF_TYPE_STR) ? (c ? "%c" : "\\0") : "%02X", c);
        }
}
int psv_sfo_dump(int in, int out) {
        sfo_header_t hdr;
        if(read(in, &hdr, sizeof(hdr))!=sizeof(hdr))return -1;
        dprintf(out, "HEADER %08X v%X, %i Entries <keys@%i,vals@%i>", hdr.magic, hdr.version, hdr.entry_count,
hdr.keys_off, hdr.vals_off); dprintf(out, "\n\nENTRY: type alig key@ val@ size lim."); sfo_entry_t
entries[hdr.entry_count];

        unsigned val_section_size = 0, key_section_size = 0;
        for (unsigned i = 0; i < hdr.entry_count; i++) {
                sfo_entry_t ent;
                read(in, &ent, sizeof(ent));
                entries[i] = ent;
                if (ent.val_off + ent.val_length > val_section_size)
                        val_section_size = ent.val_off + ent.val_length;
                if (ent.key_off > key_section_size)
                        key_section_size = ent.key_off;

                dprintf(out, "\n%5i: %4i %4i %4i %4i %4i %4i", i, ent.type, ent.alignment, ent.key_off, ent.val_off,
                        ent.val_length, ent.val_limit);
        }
        uint8_t c;
        uint32_t end_pad = hdr.keys_off < hdr.vals_off ? hdr.keys_off : hdr.vals_off;
        for (size_t i = (sizeof(hdr) + hdr.entry_count * sizeof(sfo_entry_t));
             i < end_pad && read(in, &c, sizeof(c)) > 0; i++) {
                dprintf(out, "%02X", c);
        }
        if (hdr.keys_off > hdr.vals_off) {
                fprintf(stderr, "WARNING Untested Value-before-keys dumping\n");
                //TODO skip padding ??
                psv_sfo_dump_val(in, out, hdr, entries, val_section_size);
                psv_sfo_dump_key(in, out, hdr, entries);
        } else {
                psv_sfo_dump_key(in, out, hdr, entries);
                psv_sfo_dump_val(in, out, hdr, entries, val_section_size);
        }
        dprintf(out, "\n");
        return 0;
}
*/
static ssize_t blank(void* fd, const void* buf, size_t len) { return len; }

void psv_sfo_hydrate(int count, char** keys, char** vals, sfo_entry_t* entries) {
	for (int i = 0; i < count; i++) {
		sfo_entry_t* entry = entries + i;
		if (entry->alignment == 0xFF) {
			entry->alignment = 4;
		}
		if (entry->type == 0xFF) {
			entry->type = (uint8_t)(vals[i][0] == '0' && (vals[i][1] == 'x') ? PSF_TYPE_U32 : PSF_TYPE_STR);
		}
		if (entry->val_length == 0xFFFFFFFF) {
			entry->val_length = (uint32_t)(entry->type == PSF_TYPE_U32 ? sizeof(uint32_t) : strlen(vals[i]) + 1);
		}
		if (entry->val_limit == 0xFFFFFFFF) {
			entry->val_limit = ALIGN(entry->val_length);
		}
		if (entry->key_off == 0xFFFF) {
			entry->key_off = (uint16_t)(i ? entries[i - 1].key_off + strlen(keys[i - 1]) + 1 : 0);
		}
		if (entry->val_off == 0xFFFFFFFF) {
			entry->val_off = i ? entries[i - 1].val_off + entries[i - 1].val_limit : 0;
		}
	}
}

ssize_t psv_sfo_emit(int count, char** keys, char** vals, sfo_entry_t* entries, sfo_emitter_t emitter, void* fd) {
	if (!emitter) {
		emitter = blank;
	}
	/* emit HEADER */
	ssize_t sum      = 0;
	size_t  keys_off = sizeof(sfo_header_t) + count * sizeof(sfo_entry_t);
	size_t  vals_off = keys_off;
	for (int i = 0; i < count; i++) {
		vals_off += strlen(keys[i]) + 1;
	}
	sfo_header_t sfo_header = {
	    .magic       = PSF_MAGIC,
	    .version     = PSF_VERSION,
	    .keys_off    = (uint32_t)keys_off,
	    .vals_off    = (uint32_t)ALIGN(vals_off),
	    .entry_count = (uint32_t)count,
	};
	sum += emitter(fd, &sfo_header, sizeof(sfo_header));
	for (int i = 0; i < count; i++) {
		sum += emitter(fd, entries + i, sizeof(*entries));
	}
	for (int i = 0; i < count; i++) {
		sum += emitter(fd, keys[i], strlen(keys[i]) + 1);
	}
	sum += emitter(fd, "\0\0\0\0", ALIGN(vals_off) - vals_off);
	for (int i = 0; i < count; i++) {
		sfo_entry_t* entry = &entries[i];
		// fprintf(stderr, ">>%s:%i*%i/%i~%i@%i-%i=\"%s\"\n", keys[i], entry->type, entry->val_length,
		// entry->val_limit, entry->alignment, entry->key_off, entry->val_off, vals[i]);
		if (entries[i].type == PSF_TYPE_U32) {
			struct little {
				uint32_t i;
			} val = {(uint32_t)strtoul(vals[i], NULL, 0)};
			sum += emitter(fd, &val, sizeof(val));
		} else {
			sum += emitter(fd, vals[i], entries[i].val_length);
			for (int remain = ALIGN(entries[i].val_limit) - entries[i].val_length; remain > 0; remain--) {
				//				fprintf(stderr, "%i [%i] %li\n", i,
				// ALIGN(entries[i].val_limit) - entries[i].val_length, sum);
				sum += emitter(fd, "\0", 1);
			}
			//			emitter(fd, "\0\0\0\0", ALIGN(entries[i].val_length) -
			// entries[i].val_length) sum += emitter(fd, "\0\0\0\0", ALIGN(entries[i].val_length) -
			// entries[i].val_length);
		}
	}
	return sum;
}

#endif