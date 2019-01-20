/**
# NAME
self - Signed Executable and Linkable Format

# DESCRIPTION
SELF files start with a signature overhead followed by a standard ELF file.
Inner ELF file can be compressed (gzip), encrypted (AES CTR), signed (ECDSA + HMAC-SHA1).

# FORMAT

  SELF_HEADER
  SELF_APP
  ELF32_EHDR
  ELF32_PHDR
  SELF_VERSION
  SELF_CTRL_5
  SELF_CTRL_6
  SELF_CTRL_7
  ELF

# SEE ALSO
  - <self.h>
  - https://vitadevwiki.com/vita/SELF_File_Format
*/
#ifndef SELF_H
#define SELF_H
#include <inttypes.h>

#define SELF_HEADER_TYPE_SELF 1
#define SELF_HEADER_TYPE_RVK 2
#define SELF_HEADER_TYPE_PKG 3
#define SELF_HEADER_TYPE_SPP 4

#define SELF_HEADER_VERSION_PS3 2
#define SELF_HEADER_VERSION_PSV 3

#define SELF_SEGMENT_UNCOMPRESSED 1
#define SELF_SEGMENT_COMPRESSED 2
#define SELF_SEGMENT_ENCRYPTED 1
#define SELF_SEGMENT_PLAIN 2

#define SELF_APPINFO_TYPE_LV0 1
#define SELF_APPINFO_TYPE_LV1 2
#define SELF_APPINFO_TYPE_LV2 3
#define SELF_APPINFO_TYPE_APP 4
#define SELF_APPINFO_TYPE_SPU 5
#define SELF_APPINFO_TYPE_SECLDR 6
#define SELF_APPINFO_TYPE_APPLDR 7
#define SELF_APPINFO_TYPE_NPDRM 8l
#define SELF_APPINFO_TYPE_SM 11
#define SELF_APPINFO_TYPE_SYSUSR 13

#define SELF_APPINFO_AUTH_NORMAL 1
#define SELF_APPINFO_AUTH_SAFE 2
#define SELF_APPINFO_AUTH_SECRET 3

typedef struct {
	uint32_t magic;             /* 53434500 = SCE\0 */
	uint32_t version;           /* header version (PS3=2,PSV=3)*/
	uint16_t sdk_type;          /* used to select the decryption key*/
	uint16_t header_type;       /* 1=self, 2=rvk, 3=pkg, 4=spp */
	uint32_t metadata_offset;   /* (checksums_offset) Must be at least 20 bytes before the end of the header */
	uint64_t header_len;        /* self header length (0x100)*/
	uint64_t elf_filesize;      /* ELF file length */
	uint64_t self_filesize;     /* SELF file length */
	uint64_t unknown;           /* must be 0 */
	uint64_t self_offset;       /* SELF offset (0x4) */
	uint64_t app_offset;        /* SELF_app offset (0x80) */
	uint64_t elf_offset;        /* ELF #1 offset (0xA0) */
	uint64_t phdr_offset;       /* program header offset */
	uint64_t shdr_offset;       /* section header offset */
	uint64_t section_offset;    /* section info offset */
	uint64_t sceversion_offset; /* version offset */
	uint64_t ctrl_offset;       /* control info offset */
	uint64_t ctrl_size;         /* control info size */
	uint64_t padding;
} SELF_header;

typedef struct {
	uint64_t authid;    /* auth id (see SELF_APPINFO_AUTH_*) */
	uint32_t vendor_id; /* vendor id (0) */
	uint32_t self_type; /* app type (see SELF_APPINFO_TYPE_*) */
	uint64_t version;   /* app version */
	uint64_t padding;   /* (0) */
} SELF_app;

typedef struct {
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t unk4;
} SELF_version;

typedef struct {
	uint32_t type;
	uint32_t size;
	uint32_t unk;
	uint32_t pad;
} SELF_ctrl;

typedef struct {
	SELF_ctrl common;
	char      unk[0x100];
} SELF_ctrl_5;

typedef struct {
	SELF_ctrl common;
	uint32_t  unk1;
	char      unk2[0xFC];
} SELF_ctrl_6;

typedef struct {
	SELF_ctrl common;
	char      unk[0x40];
} SELF_ctrl_7;

typedef struct {
	uint64_t offset;
	uint64_t length;
	uint32_t compression;
	uint32_t unk20;
	uint32_t encryption;
	uint32_t unk28;
} SELF_segment;

#endif