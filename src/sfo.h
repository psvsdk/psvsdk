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
*/


#ifndef SFO_H
#define SFO_H
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PSF_MAGIC 0x46535000
#define PSF_VERSION 0x00000101
//#define PSF_TYPE_SPE 0
#define PSF_TYPE_STR 2u
#define PSF_TYPE_U32 4u
#define little __attribute__((packed, scalar_storage_order("little-endian")))
#define ALIGN(V) (((V) + ((4) - 1)) & ~((4) - 1))

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
	uint32_t val_size;
	uint32_t val_limit;
	uint32_t val_off;
} sfo_entry_t;

typedef struct {
	const char* key;
	uint32_t    val_i; // hold the 'val_limit' size if `val_s` is set
	const char* val_s;
} psv_entry_t;

int psv_sfo_dump(int in, int out) {
	sfo_header_t hdr;
	read(in, &hdr, sizeof(hdr));
	dprintf(out, "HEADER %08X v%X, %i Entries <keys@%i,vals@%i>", hdr.magic, hdr.version, hdr.entry_count,
		hdr.keys_off, hdr.vals_off);
	dprintf(out, "\n\nENTRY: type alig key@ val@ size lim.");
	sfo_entry_t entries[hdr.entry_count];
	unsigned last_val = 0;
	for (unsigned i = 0; i < hdr.entry_count; i++) {
		sfo_entry_t ent;
		read(in, &ent, sizeof(ent));
		entries[i] = ent;
		if (ent.val_off + ent.val_size > last_val)
			last_val = ent.val_off + ent.val_size;

		dprintf(out, "\n%5i: %4i %4i %4i %4i %4i %4i", i, ent.type, ent.alignment, ent.key_off, ent.val_off,
			ent.val_size, ent.val_limit);
	}
	if (hdr.keys_off > hdr.vals_off) {
		fprintf(stderr, "Value before keys are not supported for dumping\n");
		return -1;
	}
	uint8_t c;
	for (size_t i = (sizeof(sfo_header_t) + hdr.entry_count * sizeof(sfo_entry_t));
	     i < hdr.keys_off && read(in, &c, sizeof(c)) > 0; i++) {
		dprintf(out, "%02X", c);
	}

	dprintf(out, "\n\n  KEY:");
	for (unsigned i = hdr.keys_off; i < hdr.vals_off && read(in, &c, sizeof(c)) > 0; i++) {
		for (unsigned e = 0; e < hdr.entry_count; e++) {
			if (i == hdr.keys_off + entries[e].key_off) {
				dprintf(out, "\n%5i: ", e);
			}
		}
		dprintf(out, c ? "%c" : "\\0", c);
	}

	sfo_entry_t* found_ent = NULL;
	dprintf(out, "\n\nVALUE:");
	for (unsigned i = 0; i < last_val && read(in, &c, sizeof(c)) > 0; i++) {
		for (unsigned e = 0; e < hdr.entry_count; e++) {
			if (i == entries[e].val_off) {
				found_ent = &entries[e];
				dprintf(out, "\n%5i: ", e);
			}
		}
		// if(found_ent && found_ent->val_size)
		dprintf(out, (found_ent && found_ent->type == PSF_TYPE_STR) ? (c ? "%c" : "\\0") : "%02X", c);
	}
	dprintf(out, "\n");
	return 0;
}

ssize_t psv_sfo_emit(psv_entry_t* first, psv_entry_t* last, ssize_t (*emiter)(void*, const void*, size_t), void* fd) {
	for (psv_entry_t* e = first; e < last; e++) fprintf(stderr, "%s = /%s/%08X\n", e->key, e->val_s, e->val_i);

	/* emit HEADER */
	ssize_t sum      = 0;
	size_t  keys_off = sizeof(sfo_header_t) + sizeof(sfo_entry_t) * (last - first);
	size_t  vals_off = keys_off;
	for (psv_entry_t* e = first; e < last; e++) {
		vals_off += strlen(e->key) + 1;
	}
	sfo_header_t sfo_header = {
	    .magic       = PSF_MAGIC,
	    .version     = PSF_VERSION,
	    .keys_off    = (uint32_t) keys_off,
	    .vals_off    = (uint32_t) ALIGN(vals_off),
	    .entry_count = (uint32_t) (last - first),
	};
	sum += emiter(fd, &sfo_header, sizeof(sfo_header_t));

	/* emit ENTRIES */
	uint32_t val_off = 0;
	uint16_t key_off = 0;
	for (psv_entry_t* e = first; e < last; e++) {
		sfo_entry_t entry = {
		    .key_off   = key_off,
		    .alignment = sizeof(e->val_i),
		    .type      = (uint8_t) (e->val_s ? PSF_TYPE_STR : PSF_TYPE_U32),
		    .val_size  = e->val_s ? e->val_i : sizeof(e->val_i),
		    .val_limit = ALIGN(e->val_s ? e->val_i : sizeof(e->val_i)),
		    .val_off   = val_off,
		};
		if (entry.val_size > entry.val_limit) {
			fprintf(stderr, "Value for %s is over limit (%u>%u)", e->key, entry.val_size, entry.val_limit);
		}
		sum += emiter(fd, &entry, sizeof(entry));
		val_off += entry.val_limit;
		key_off += strlen(e->key) + 1;
	}

	/* emit KEYS */
	for (psv_entry_t* e = first; e < last; e++) {
		sum += emiter(fd, e->key, strlen(e->key) + 1);
	}

	/* emit PADDING */
	sum += emiter(fd, "\0\0\0\0", ALIGN(vals_off) - vals_off);

	/* emit VALS */
	for (psv_entry_t* e = first; e < last; e++) {
		if (e->val_s) {
			sum += emiter(fd, e->val_s, e->val_i);
			sum += emiter(fd, "\0\0\0\0", ALIGN(e->val_i) - e->val_i);
		} else {
			struct little {uint32_t i;} val = {e->val_i};
			sum += emiter(fd, &val, sizeof(val));
		}
	}
	return sum;
}

#endif