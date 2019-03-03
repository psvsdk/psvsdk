/**
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
*/

#ifndef VPK_H
#define VPK_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#define VPK_LOCAL_HEADER 0x04034b50
#define VPK_DIR_HEADER 0x02014b50
#define VPK_END_RECORD 0x06054b50
#define VPK_MADE_BY 0x031e
#define VPK_DIR_VERSION 0x000a
#define VPK_FILE_VERSION 0x0014
#define VPK_EXTERNAL_DIR 0x41ed0010
#define VPK_EXTERNAL_FILE 0x81a40000
#define VPK_MAX_FILE 128
#define VPK_MAX_PATH 256
#define little __attribute__((packed, scalar_storage_order("little-endian")))

typedef struct little {
	uint32_t       type;
	uint16_t       made, version, flags, method;
	uint32_t       modtime, crc, size, size_;
	uint16_t       namelen, z1, z2, z3, z4;
	uint32_t       attrs, offset;
	char           name[VPK_MAX_PATH];
	struct _vpk_s* vpk;
} vpk_entry_t;

typedef struct little {
	uint32_t type;
	uint16_t a, b, c, d;
	uint32_t size, start;
	uint16_t e;
} vpk_footer_t;

typedef struct _vpk_s {
	int         fd;
	uint16_t    num_files;
	uint32_t    total;
	vpk_entry_t files[VPK_MAX_FILE];
} vpk_t;

static void vpk_entry_write(vpk_t* vpk, vpk_entry_t* ent, uint32_t type) {
	vpk->total += write(vpk->fd, &ent->type, (type == VPK_DIR_HEADER ? offsetof(vpk_entry_t, version) : offsetof(vpk_entry_t, made)));
	vpk->total +=
	    write(vpk->fd, &ent->version, (type == VPK_DIR_HEADER ? offsetof(vpk_entry_t, name) : offsetof(vpk_entry_t, z2)) - offsetof(vpk_entry_t, version));
	vpk->total += write(vpk->fd, ent->name, ent->namelen);
}

static vpk_entry_t* vpk_entry_add(vpk_t* vpk, const char* name, uint32_t attrs) {
	if (vpk->num_files >= (sizeof(vpk->files) / sizeof(*vpk->files)))
		return NULL;
	vpk_entry_t* ent = vpk->files + vpk->num_files++;
	*ent             = (vpk_entry_t){.made    = VPK_MADE_BY,
                             .vpk     = vpk,
                             .offset  = vpk->total,
                             .attrs   = attrs,
                             .namelen = (uint16_t)strlen(name),
                             .version = (uint16_t)(ent->attrs == VPK_EXTERNAL_DIR ? VPK_DIR_VERSION : VPK_FILE_VERSION)};
	strncpy(ent->name, name, sizeof(ent->name) - 1);
	return ent;
}

vpk_entry_t* vpkFileOpen(vpk_t* vpk, const char* name, uint32_t size) {
	vpk_entry_t* ent = vpk_entry_add(vpk, name, VPK_EXTERNAL_FILE);
	ent->size_ = ent->size = size;
	vpk_entry_write(vpk, ent, ent->type = VPK_LOCAL_HEADER);
	return ent;
}
ssize_t vpkFileWrite(vpk_entry_t* ent, const void* data, ssize_t bytes) {
	ssize_t wrote = write(ent->vpk->fd, data, bytes);
	ent->vpk->total += wrote;
	return wrote;
}

vpk_entry_t* vpkDir(vpk_t* vpk, const char* name) {
	vpk_entry_t* ent = vpk_entry_add(vpk, name, VPK_EXTERNAL_DIR);
	vpk_entry_write(vpk, ent, ent->type = VPK_LOCAL_HEADER);
	return ent;
}
int vpkClose(vpk_t* vpk) {
	uint32_t start = vpk->total;
	for (vpk_entry_t* ent = vpk->files; ent < vpk->files + vpk->num_files; ent++)
		vpk_entry_write(vpk, ent, ent->type = VPK_DIR_HEADER);
	write(vpk->fd, &(vpk_footer_t){VPK_END_RECORD, 0, 0, vpk->num_files, vpk->num_files, vpk->total - start, start, 0}, sizeof(vpk_footer_t));
	return close(vpk->fd);
}

#endif