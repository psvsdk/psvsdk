/**
# NAME
velf - Vita-specific ELF

# DESCRIPTION

A velf provide the following additional informations:
- import: variable and function that hav been stubed with ARM code at build time
- export: variable and function stubs declaration that will be resolved at ELF loading.
- relocations: vita-compatible relocation list of variable and function

# VELF LAYOUT OVERVIEW

	ELF Header:
	- Class: ELF32
	- Data: LitleEndian
	- Machine: ARM
	- Flags: 0x5000400 (EABI.v5 | HardFloat)
	...
	- Type: 0xfe04 (SCE_RELEXEC)
	- EntryPoint: 0x2a10 (sceModule VAddress, see bellow)
	Program Headers:
	- Read + Executable segment:
		- text: the main executable payload
		- stubs: bouncer to the external function
		- sceModule: refered by elf EntryPoint
	- Read + Write segment:
		- .data
	- SCE_RELA segment (not loaded in RAM)
		- relocation info for functions + variables
	Section Headers are not used

# RELOCATION

As opposed to static executable wich can only be run from a specific address,
relocatable ELF can be executed from any address, wich is handy if you want to
load multiple program at the same times. But in order to do that, the loader
must know which symbols/addresses needs to be adapted to this given addresse
using a relocation table.

In VELF, this table found as the last program segment (0x10-aligned no RWX)

This table can define either long or short relocation entries.
The (default) long relocation entries cover a larger scope of symbol offset.

# MODULE INFO

In VELF, this struct is given by the ELF Header EntryPoint attribut.
It defines the current module information that are required to be loaded:
The module name, type, entrypoint, imports, exports, SDK version ...

# IMPORT/EXPORT

When linking to a *_stub libraries, it library fake the existence of the
required fonction/variable in order to compile and instead, setup a section
that contain all the required information for psv-velf to organize them into
an "import" list that the PSVita loader will understand and resolve so your
application will seemlessly be able to call external functions.

# CREDIT

based on the vitasdk vita-elf-create source:
https://github.com/vitasdk/vita-toolchain/

*/
#ifndef VITA_ELF_H
#define VITA_ELF_H

#include <endian.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// import header from our local "include/libelf/*" directory
#include "libelf/gelf.h" /* for extra sanity check */
#include "libelf/libelf.h"
extern char you_are_using_system_libelf_h[ELF_C_WRITE == 2 ? 1 : -1];

#include "varray.h"

#define DIE(...)                  \
	{                               \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n");        \
		goto failure;                 \
	}
#define ASSERT(cond)                      \
	if (!(cond)) {                          \
		DIE("Assertion failed: (" #cond ")"); \
	}
#define ELF_ASSERT(cond)                      \
	if (!(cond)) {                              \
		DIE(#cond " failed: %s", elf_errmsg(-1)); \
	}
#define LOG(...) fprintf(getenv("DEBUG") ? stderr : stdin, __VA_ARGS__)

typedef struct {
	const char* name;
	uint32_t    nid;
} vita_export_symbol;

typedef struct {
	const char*          name;
	uint32_t             version;
	int                  syscall;
	size_t               function_n;
	vita_export_symbol** functions;
	size_t               variable_n;
	vita_export_symbol** variables;
	uint32_t             nid;
} vita_library_export;

typedef struct {
	char                  name[27];
	uint8_t               ver_major;
	uint8_t               ver_minor;
	uint16_t              attributes;
	uint32_t              nid;
	bool                  is_image_module;
	const char*           bootstart;
	const char*           start;
	const char*           stop;
	const char*           exit;
	size_t                lib_n;
	vita_library_export** libs;
} vita_export_t;

/* These fields must always come at the beginning of the nid-bearing structs */
typedef struct {
	char*    name;
	uint32_t nid;
} vita_imports_common_fields;

typedef struct {
	char*    name;
	uint32_t nid;
} vita_imports_stub_t;

typedef struct {
	char*                 name;
	uint32_t              nid;
	bool                  is_kernel;
	vita_imports_stub_t** functions;
	vita_imports_stub_t** variables;
	int                   n_functions;
	int                   n_variables;
	uint32_t              flags;
} vita_imports_lib_t;

typedef struct {
	char*                name;
	uint32_t             nid;
	vita_imports_lib_t** libs;
	int                  n_libs;
} vita_imports_module_t;

/* Convenience representation of a symtab entry */
typedef struct velf_symbol_t {
	const char* name;
	Elf32_Addr  value;
	uint8_t     type;
	uint8_t     binding;
	int         shndx;
} velf_symbol_t;

typedef struct velf_rela_t {
	uint8_t        type;
	velf_symbol_t* symbol;
	Elf32_Addr     offset;
	Elf32_Sword    addend;
} velf_rela_t;

typedef struct velf_rela_table_t {
	velf_rela_t* relas;
	int          num_relas;

	int target_ndx;

	struct velf_rela_table_t* next;
} velf_rela_table_t;

typedef struct velf_stub_t {
	Elf32_Addr addr;
	uint32_t   library_nid;
	uint32_t   target_nid;

	velf_symbol_t* symbol;

	vita_imports_lib_t*  library;
	vita_imports_stub_t* target;
} velf_stub_t;

typedef struct velf_segment_info_t {
	Elf32_Word type;  /* Segment type */
	Elf32_Addr vaddr; /* Top of segment space on TARGET */
	Elf32_Word memsz; /* Size of segment space */

	/* vaddr_top/vaddr_bottom point to a reserved, unallocated memory space that
	 * represents the segment space in the HOST.  This space can be used as
	 * pointer targets for translated data structures. */
	const void* vaddr_top;
	const void* vaddr_bottom;
} velf_segment_info_t;

typedef struct velf_t {
	FILE* file;
	int   mode;
	Elf*  elf;

	velf_rela_table_t* rela_tables;

	int            symtab_ndx;
	velf_symbol_t* symtab;
	int            num_symbols;

	velf_stub_t* fstubs;
	varray       fstubs_va;
	int          num_fstubs;

	velf_stub_t* vstubs;
	varray       vstubs_va;
	int          num_vstubs;

	velf_segment_info_t* segments;
	int                  num_segments;
} velf_t;

#define VELF_SEC_FSTUB ".vitalink.fstubs"
#define VELF_SEC_VSTUB ".vitalink.vstubs"

#define R_ARM_NONE            0
#define R_ARM_ABS32           2
#define R_ARM_REL32           3
#define R_ARM_THM_CALL        10
#define R_ARM_CALL            28
#define R_ARM_JUMP24          29
#define R_ARM_THM_JUMP24      30
#define R_ARM_TARGET1         38
#define R_ARM_SBREL31         39
#define R_ARM_V4BX            40
#define R_ARM_TARGET2         41
#define R_ARM_PREL31          42
#define R_ARM_MOVW_ABS_NC     43
#define R_ARM_MOVT_ABS        44
#define R_ARM_MOVW_PREL_NC    45
#define R_ARM_MOVT_PREL       46
#define R_ARM_THM_MOVW_ABS_NC 47
#define R_ARM_THM_MOVT_ABS    48
#define R_ARM_THM_PC11        102

#define STB_NUM 3

#ifdef SHT_ARM_EXIDX
#undef SHT_ARM_EXIDX
#endif

#define SHT_ARM_EXIDX 0x70000001

/* SCE-specific definitions for e_type: */
#define ET_SCE_EXEC       0xFE00 /* SCE Executable file */
#define ET_SCE_RELEXEC    0xFE04 /* SCE Relocatable file */
#define ET_SCE_STUBLIB    0xFE0C /* SCE SDK Stubs */
#define ET_SCE_DYNAMIC    0xFE18 /* Unused */
#define ET_SCE_PSPRELEXEC 0xFFA0 /* Unused (PSP ELF only) */
#define ET_SCE_PPURELEXEC 0xFFA4 /* Unused (SPU ELF only) */
#define ET_SCE_UNK        0xFFA5 /* Unknown */

/* SCE-specific definitions for sh_type: */
#define SHT_SCE_RELA    0x60000000 /* SCE Relocations */
#define SHT_SCENID      0x61000001 /* Unused (PSP ELF only) */
#define SHT_SCE_PSPRELA 0x700000A0 /* Unused (PSP ELF only) */
#define SHT_SCE_ARMRELA 0x700000A4 /* Unused (PSP ELF only) */

/* SCE-specific definitions for p_type: */
#define PT_SCE_RELA    0x60000000 /* SCE Relocations */
#define PT_SCE_COMMENT 0x6FFFFF00 /* Unused */
#define PT_SCE_VERSION 0x6FFFFF01 /* Unused */
#define PT_SCE_UNK     0x70000001 /* Unknown */
#define PT_SCE_PSPRELA 0x700000A0 /* Unused (PSP ELF only) */
#define PT_SCE_PPURELA 0x700000A4 /* Unused (SPU ELF only) */

#define NID_MODULE_STOP        0x79F8E492
#define NID_MODULE_EXIT        0x913482A9
#define NID_MODULE_START       0x935CD196
#define NID_MODULE_BOOTSTART   0x5C424D40
#define NID_MODULE_INFO        0x6C2224BA
#define NID_PROCESS_PARAM      0x70FBA1E7
#define NID_MODULE_SDK_VERSION 0x936C8A78

#define PSP2_SDK_VERSION 0x03570011

typedef union {
	Elf32_Word r_short : 4;
	struct {
		Elf32_Word r_short : 4;
		Elf32_Word r_symseg : 4;
		Elf32_Word r_code : 8;
		Elf32_Word r_datseg : 4;
		Elf32_Word r_offset_lo : 12;
		Elf32_Word r_offset_hi : 20;
		Elf32_Word r_addend : 12;
	} r_short_entry;
	struct {
		Elf32_Word r_short : 4;
		Elf32_Word r_symseg : 4;
		Elf32_Word r_code : 8;
		Elf32_Word r_datseg : 4;
		Elf32_Word r_code2 : 8;
		Elf32_Word r_dist2 : 4;
		Elf32_Word r_addend;
		Elf32_Word r_offset;
	} r_long_entry;
	struct {
		Elf32_Word r_word1;
		Elf32_Word r_word2;
		Elf32_Word r_word3;
	} r_raw_entry;
} velf_reloc;

static const char* section_names[] = {
    ".sceModuleInfo.rodata", /* The sce_modinfo, sce_param_libc and sce_process_param structures */
    ".sceLib.ent",           /* All sce_module_exports structures */
    ".sceExport.rodata",     /* The tables referenced by sce_module_exports */
    ".sceLib.stubs",         /* All sce_module_imports structures */
    ".sceImport.rodata",     /* Misc data referenced by sce_module_imports */
    ".sceFNID.rodata",       /* The imported function nid arrays */
    ".sceFStub.rodata",      /* The imported function pointer arrays */
    ".sceVNID.rodata",       /* The imported variable nid arrays */
    ".sceVStub.rodata"       /* The imported variable pointer arrays */
};

/* Must only contain Elf32_Words, as it's used as Elf32_Words[] */
typedef struct {
	Elf32_Word sceModuleInfo_rodata; /* 4 Hold the sce_modinfo, sce_param_libc and sce_process_param structures */
	Elf32_Word sceLib_ent;           /* 4 All sce_module_exports structures */
	Elf32_Word sceExport_rodata;     /* 8 The tables referenced by sce_module_exports */
	Elf32_Word sceLib_stubs;         /* 4 All sce_module_imports structures */
	Elf32_Word sceImport_rodata;     /* 4 Misc data referenced by sce_module_imports */
	Elf32_Word sceFNID_rodata;       /* 4 The imported function nid arrays */
	Elf32_Word sceFStub_rodata;      /* 4 The imported function pointer arrays */
	Elf32_Word sceVNID_rodata;       /* 4 The imported variable nid arrays */
	Elf32_Word sceVStub_rodata;      /* 8 The imported variable pointer arrays */
} sce_section_sizes_t;

#include "velf-defs.h"

static void free_rela_table(velf_rela_table_t* rtable);

vita_imports_lib_t* vita_imports_lib_new(const char* name, bool kernel, uint32_t nid, int n_functions, int n_variables) {
	vita_imports_lib_t* lib = malloc(sizeof(*lib));
	if (lib == NULL)
		return NULL;

	memset(lib, 0, sizeof(vita_imports_lib_t));

	lib->name        = strdup(name);
	lib->nid         = nid;
	lib->is_kernel   = kernel;
	lib->n_functions = n_functions;
	lib->n_variables = n_variables;
	lib->functions   = calloc(n_functions, sizeof(*lib->functions));
	lib->variables   = calloc(n_variables, sizeof(*lib->variables));
	return lib;
}

void vita_imports_stub_free(vita_imports_stub_t* stub) {
	if (stub) {
		free(stub->name);
		free(stub);
	}
}

void vita_imports_lib_free(vita_imports_lib_t* lib) {
	if (lib) {
		int i;
		for (i = 0; i < lib->n_variables; i++) {
			vita_imports_stub_free(lib->variables[i]);
		}
		for (i = 0; i < lib->n_functions; i++) {
			vita_imports_stub_free(lib->functions[i]);
		}
		free(lib->name);
		free(lib);
	}
}

void vita_imports_module_free(vita_imports_module_t* mod) {
	if (mod) {
		int i;
		for (i = 0; i < mod->n_libs; i++) {
			vita_imports_lib_free(mod->libs[i]);
		}
		free(mod->name);
		free(mod);
	}
}

static int load_stubs(Elf_Scn* scn, int* num_stubs, velf_stub_t** stubs, char* name) {
	GElf_Shdr    shdr;
	Elf_Data*    data;
	uint32_t*    stub_data;
	int          chunk_offset, total_bytes;
	velf_stub_t* curstub;
	int          old_num;

	gelf_getshdr(scn, &shdr);

	old_num    = *num_stubs;
	*num_stubs = old_num + shdr.sh_size / 16;
	*stubs     = realloc(*stubs, *num_stubs * sizeof(velf_stub_t));
	memset(&(*stubs)[old_num], 0, sizeof(velf_stub_t) * shdr.sh_size / 16);

	name = strrchr(name, '.') + 1;

	curstub = *stubs;
	curstub = &curstub[*num_stubs - (shdr.sh_size / 16)];

	data        = NULL;
	total_bytes = 0;
	while (total_bytes < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {

		for (stub_data = (uint32_t*)data->d_buf, chunk_offset = 0; chunk_offset < data->d_size; stub_data += 4, chunk_offset += 16) {
			curstub->addr           = shdr.sh_addr + data->d_off + chunk_offset;
			curstub->library        = vita_imports_lib_new(name, false, 0, 0, 0);
			curstub->library->flags = le32toh(stub_data[0]);
			curstub->library_nid    = le32toh(stub_data[1]);
			curstub->target_nid     = le32toh(stub_data[2]);
			curstub++;
		}

		total_bytes += data->d_size;
	}

	return 1;
}

static int load_symbols(velf_t* ve, Elf_Scn* scn) {
	GElf_Shdr      shdr;
	Elf_Data*      data;
	GElf_Sym       sym;
	int            total_bytes;
	int            data_beginsym, symndx;
	velf_symbol_t* cursym;

	if (elf_ndxscn(scn) == ve->symtab_ndx)
		return 1; /* Already loaded */

	if (ve->symtab != NULL)
		DIE("ELF file appears to have multiple symbol tables!");

	gelf_getshdr(scn, &shdr);

	ve->num_symbols = shdr.sh_size / shdr.sh_entsize;
	ve->symtab      = calloc(ve->num_symbols, sizeof(velf_symbol_t));
	ve->symtab_ndx  = elf_ndxscn(scn);

	data        = NULL;
	total_bytes = 0;
	while (total_bytes < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {

		data_beginsym = data->d_off / shdr.sh_entsize;
		for (symndx = 0; symndx < data->d_size / shdr.sh_entsize; symndx++) {
			if (gelf_getsym(data, symndx, &sym) != &sym) {
				DIE("gelf_getsym() failed");
			}

			cursym = ve->symtab + symndx + data_beginsym;

			cursym->name    = elf_strptr(ve->elf, shdr.sh_link, sym.st_name);
			cursym->value   = sym.st_value;
			cursym->type    = GELF_ST_TYPE(sym.st_info);
			cursym->binding = GELF_ST_BIND(sym.st_info);
			cursym->shndx   = sym.st_shndx;
		}

		total_bytes += data->d_size;
	}

	return 1;
failure:
	return 0;
}

#define THUMB_SHUFFLE(x) ((((x)&0xFFFF0000) >> 16) | (((x)&0xFFFF) << 16))
static uint32_t decode_rel_target(uint32_t data, int type, uint32_t addr) {
	uint32_t upper, lower, sign, j1, j2, imm10, imm11;
	switch (type) {
	case R_ARM_NONE:
	case R_ARM_V4BX:
		return 0xdeadbeef;
	case R_ARM_ABS32:
	case R_ARM_TARGET1:
		return data;
	case R_ARM_REL32:
	case R_ARM_TARGET2:
		return data + addr;
	case R_ARM_PREL31:
		return data + addr;
	case R_ARM_THM_CALL: // bl (THUMB)
		data  = THUMB_SHUFFLE(data);
		upper = data >> 16;
		lower = data & 0xFFFF;
		sign  = (upper >> 10) & 1;
		j1    = (lower >> 13) & 1;
		j2    = (lower >> 11) & 1;
		imm10 = upper & 0x3ff;
		imm11 = lower & 0x7ff;
		return addr + (((imm11 | (imm10 << 11) | (!(j2 ^ sign) << 21) | (!(j1 ^ sign) << 22) | (sign << 23)) << 1) | (sign ? 0xff000000 : 0));
	case R_ARM_CALL:   // bl/blx
	case R_ARM_JUMP24: // b/bl<cond>
		data = (data & 0x00ffffff) << 2;
		// if we got a negative value, sign extend it
		if (data & (1 << 25))
			data |= 0xfc000000;
		return data + addr;
	case R_ARM_MOVW_ABS_NC: //movw
		return ((data & 0xf0000) >> 4) | (data & 0xfff);
	case R_ARM_MOVT_ABS: //movt
		return (((data & 0xf0000) >> 4) | (data & 0xfff)) << 16;
	case R_ARM_THM_MOVW_ABS_NC: //MOVW (THUMB)
		data = THUMB_SHUFFLE(data);
		return (((data >> 16) & 0xf) << 12) | (((data >> 26) & 0x1) << 11) | (((data >> 12) & 0x7) << 8) | (data & 0xff);
	case R_ARM_THM_MOVT_ABS: //MOVT (THUMB)
		data = THUMB_SHUFFLE(data);
		return (((data >> 16) & 0xf) << 28) | (((data >> 26) & 0x1) << 27) | (((data >> 12) & 0x7) << 24) | ((data & 0xff) << 16);
	}

	fprintf(stderr, "Invalid relocation type: %d", type);
	return 0;
}

#define REL_HANDLE_NORMAL  0
#define REL_HANDLE_IGNORE  -1
#define REL_HANDLE_INVALID -2
static int get_rel_handling(int type) {
	switch (type) {
	case R_ARM_NONE:
	case R_ARM_V4BX:
		return REL_HANDLE_IGNORE;
	case R_ARM_ABS32:
	case R_ARM_TARGET1:
	case R_ARM_REL32:
	case R_ARM_TARGET2:
	case R_ARM_PREL31:
	case R_ARM_THM_CALL:
	case R_ARM_CALL:
	case R_ARM_JUMP24:
	case R_ARM_MOVW_ABS_NC:
	case R_ARM_MOVT_ABS:
	case R_ARM_THM_MOVW_ABS_NC:
	case R_ARM_THM_MOVT_ABS:
		return REL_HANDLE_NORMAL;
	}

	return REL_HANDLE_INVALID;
}

static int load_rel_table(velf_t* ve, Elf_Scn* scn) {
	Elf_Scn*  text_scn;
	GElf_Shdr shdr, text_shdr;
	Elf_Data *data, *text_data;
	GElf_Rel  rel;
	int       relndx;

	int rel_sym;
	int handling;

	velf_rela_table_t* rtable  = NULL;
	velf_rela_t*       currela = NULL;
	uint32_t           insn, target = 0;

	gelf_getshdr(scn, &shdr);

	if (!load_symbols(ve, elf_getscn(ve->elf, shdr.sh_link)))
		goto failure;

	rtable = calloc(1, sizeof(velf_rela_table_t));
	ASSERT(rtable != NULL);
	rtable->num_relas = shdr.sh_size / shdr.sh_entsize;
	rtable->relas     = calloc(rtable->num_relas, sizeof(velf_rela_t));
	ASSERT(rtable->relas != NULL);

	rtable->target_ndx = shdr.sh_info;
	text_scn           = elf_getscn(ve->elf, shdr.sh_info);
	gelf_getshdr(text_scn, &text_shdr);
	text_data = elf_getdata(text_scn, NULL);

	/* We're blatantly assuming here that both of these sections will store
	 * the entirety of their data in one Elf_Data item.  This seems to be true
	 * so far in my testing, and from the libelf source it looks like it's
	 * unlikely to allocate multiple data items on initial file read, but
	 * should be fixed someday. */
	data = elf_getdata(scn, NULL);
	for (relndx = 0; relndx < data->d_size / shdr.sh_entsize; relndx++) {
		if (gelf_getrel(data, relndx, &rel) != &rel)
			DIE("gelf_getrel() failed");

		if ((rel.r_offset - text_shdr.sh_addr) >= text_shdr.sh_size)
			continue;

		currela       = rtable->relas + relndx;
		currela->type = GELF_R_TYPE(rel.r_info);
		/* R_ARM_THM_JUMP24 is functionally the same as R_ARM_THM_CALL, however Vita only supports the second one */
		if (currela->type == R_ARM_THM_JUMP24)
			currela->type = R_ARM_THM_CALL;
		/* This one comes from libstdc++.
		 * Should be safe to ignore because it's pc-relative and already encoded in the file. */
		if (currela->type == R_ARM_THM_PC11)
			continue;
		currela->offset = rel.r_offset;

		/* Use memcpy for unaligned relocation. */
		memcpy(&insn, text_data->d_buf + (rel.r_offset - text_shdr.sh_addr), sizeof(insn));
		insn = le32toh(insn);

		handling = get_rel_handling(currela->type);

		if (handling == REL_HANDLE_IGNORE)
			continue;
		else if (handling == REL_HANDLE_INVALID)
			DIE("Invalid relocation type %d!", currela->type);

		rel_sym = GELF_R_SYM(rel.r_info);
		if (rel_sym >= ve->num_symbols)
			DIE("REL entry tried to access symbol %d, but only %d symbols loaded", rel_sym, ve->num_symbols);

		currela->symbol = ve->symtab + rel_sym;

		target = decode_rel_target(insn, currela->type, rel.r_offset);

		/* From some testing the added for MOVT/MOVW should actually always be 0 */
		if (currela->type == R_ARM_MOVT_ABS || currela->type == R_ARM_THM_MOVT_ABS)
			currela->addend = target - (currela->symbol->value & 0xFFFF0000);
		else if (currela->type == R_ARM_MOVW_ABS_NC || currela->type == R_ARM_THM_MOVW_ABS_NC)
			currela->addend = target - (currela->symbol->value & 0xFFFF);
		/* Symbol value could be OR'ed with 1 if the function is compiled in Thumb mode,
		 * however for the relocation addend we need the actual address. */
		else if (currela->type == R_ARM_THM_CALL)
			currela->addend = target - (currela->symbol->value & 0xFFFFFFFE);
		else
			currela->addend = target - currela->symbol->value;
	}

	rtable->next    = ve->rela_tables;
	ve->rela_tables = rtable;

	return 1;
failure:
	free_rela_table(rtable);
	return 0;
}

const char* elf_decode_st_type(int st_type) {
	switch (st_type) {
	case STT_NOTYPE:
		return "NOTYPE";
	case STT_OBJECT:
		return "OBJECT";
	case STT_FUNC:
		return "FUNC";
	case STT_SECTION:
		return "SECTION";
	case STT_FILE:
		return "FILE";
	case STT_COMMON:
		return "COMMON";
	case STT_TLS:
		return "TLS";
	case STT_NUM:
		return "NUM";
	}
	if (st_type >= STT_LOOS && st_type <= STT_HIOS)
		return "(OS-specific)";
	if (st_type >= STT_LOPROC && st_type <= STT_HIPROC)
		return "(Processor-specific)";
	return "(unknown)";
}

static int lookup_stub_symbols(velf_t* ve, int num_stubs, velf_stub_t* stubs, varray* stubs_va, int sym_type) {
	int            symndx;
	velf_symbol_t* cursym;
	int            stub, stubs_ndx, i, *cur_ndx;

	for (symndx = 0; symndx < ve->num_symbols; symndx++) {
		cursym = ve->symtab + symndx;

		if (cursym->binding != STB_GLOBAL)
			continue;
		if (cursym->type != STT_FUNC && cursym->type != STT_OBJECT)
			continue;
		stubs_ndx = -1;

		for (i = 0; i < stubs_va->count; i++) {
			cur_ndx = VARRAY_ELEMENT(stubs_va, i);
			if (cursym->shndx == *cur_ndx) {
				stubs_ndx = cursym->shndx;
				break;
			}
		}

		if (stubs_ndx == -1)
			continue;

		if (cursym->type != sym_type)
			DIE("Global symbol %s in section %d expected to have type %s; instead has type %s", cursym->name, stubs_ndx, elf_decode_st_type(sym_type),
			    elf_decode_st_type(cursym->type));

		for (stub = 0; stub < num_stubs; stub++) {
			if (stubs[stub].addr != cursym->value)
				continue;
			if (stubs[stub].symbol != NULL)
				DIE("Stub at %06x in section %d has duplicate symbols: %s, %s", cursym->value, stubs_ndx, stubs[stub].symbol->name, cursym->name);
			stubs[stub].symbol = cursym;
			break;
		}

		if (stub == num_stubs)
			DIE("Global symbol %s in section %d not pointing to a valid stub", cursym->name, cursym->shndx);
	}

	return 1;

failure:
	return 0;
}

static int is_valid_relsection(velf_t* ve, GElf_Shdr* rel) {
	Elf_Scn*  info;
	size_t    phnum;
	GElf_Shdr shdr;
	GElf_Phdr phdr;

	ASSERT(rel->sh_type == SHT_REL || rel->sh_type == SHT_RELA);
	ELF_ASSERT(info = elf_getscn(ve->elf, rel->sh_info));
	ELF_ASSERT(gelf_getshdr(info, &shdr));
	ELF_ASSERT(elf_getphdrnum(ve->elf, &phnum) == 0);

	if (shdr.sh_type == SHT_NOBITS) {
		shdr.sh_size = 0;
	}

	// Here we assume that every section falls into EXACTLY one segment
	// However, the ELF format allows for weird things like one section that
	// is partially in one segment and partially in another one (or even
	// multiple).
	// TODO: For robustness, consider these corner cases
	// Right now, we just assume if you have one of these messed up ELFs,
	// we don't support it because it's likely to break in other parts of this
	// code :)
	for (int i = 0; i < phnum; i++) {
		ELF_ASSERT(gelf_getphdr(ve->elf, i, &phdr));
		if (phdr.p_type != PT_LOAD) {
			continue;
		}
		// TODO: Take account of possible integer wrap-arounds
		if (phdr.p_offset <= shdr.sh_offset && shdr.sh_offset + shdr.sh_size <= phdr.p_offset + phdr.p_filesz) {
			return 1;
		}
	}

failure:
	return 0;
}

void velf_free(velf_t* ve) {
	int i;

	for (i = 0; i < ve->num_segments; i++) {
		if (ve->segments[i].vaddr_top != NULL)
			free((void*)ve->segments[i].vaddr_top);
	}

	/* free() is safe to call on NULL */
	free(ve->fstubs);
	free(ve->vstubs);
	free(ve->symtab);
	if (ve->elf != NULL)
		elf_end(ve->elf);
	if (ve->file != NULL)
		fclose(ve->file);
	free(ve);
}
int velf_load(const char* filename, velf_t* ve) {
	GElf_Ehdr ehdr;
	Elf_Scn*  scn;
	GElf_Shdr shdr;
	size_t    shstrndx;
	char*     name;

	GElf_Phdr            phdr;
	size_t               segment_count, segndx, loaded_segments;
	velf_segment_info_t* curseg;

	ELF_ASSERT(elf_version(EV_CURRENT) != EV_NONE);
	ASSERT(varray_init(&ve->fstubs_va, sizeof(int), 8));
	ASSERT(varray_init(&ve->vstubs_va, sizeof(int), 4));

	if ((ve->file = fopen(filename, "rb")) == NULL) {
		DIE("open %s failed", filename);
	}

	ELF_ASSERT(ve->elf = elf_begin(fileno(ve->file), ELF_C_READ, NULL));

	if (elf_kind(ve->elf) != ELF_K_ELF)
		DIE("%s is not an ELF file", filename);

	ELF_ASSERT(gelf_getehdr(ve->elf, &ehdr));

	if (ehdr.e_machine != EM_ARM)
		DIE("%s is not an ARM binary", filename);

	if (ehdr.e_ident[EI_CLASS] != ELFCLASS32 || ehdr.e_ident[EI_DATA] != ELFDATA2LSB)
		DIE("%s is not a 32-bit, little-endian binary", filename);

	ELF_ASSERT(elf_getshdrstrndx(ve->elf, &shstrndx) == 0);

	scn = NULL;

	while ((scn = elf_nextscn(ve->elf, scn)) != NULL) {
		ELF_ASSERT(gelf_getshdr(scn, &shdr));

		ELF_ASSERT(name = elf_strptr(ve->elf, shstrndx, shdr.sh_name));

		if (shdr.sh_type == SHT_PROGBITS && strncmp(name, VELF_SEC_FSTUB, strlen(VELF_SEC_FSTUB)) == 0) {
			int ndxscn = elf_ndxscn(scn);
			varray_push(&ve->fstubs_va, &ndxscn);
			if (!load_stubs(scn, &ve->num_fstubs, &ve->fstubs, name))
				goto failure;
		} else if (shdr.sh_type == SHT_PROGBITS && strncmp(name, VELF_SEC_VSTUB, strlen(VELF_SEC_VSTUB)) == 0) {
			int ndxscn = elf_ndxscn(scn);
			varray_push(&ve->vstubs_va, &ndxscn);
			if (!load_stubs(scn, &ve->num_vstubs, &ve->vstubs, name))
				goto failure;
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			if (!load_symbols(ve, scn))
				goto failure;
		} else if (shdr.sh_type == SHT_REL) {
			if (!is_valid_relsection(ve, &shdr))
				continue;
			if (!load_rel_table(ve, scn))
				goto failure;
		} else if (shdr.sh_type == SHT_RELA) {
			if (!is_valid_relsection(ve, &shdr))
				continue;
			fprintf(stderr, "RELA sections currently unsupported");
			goto failure;
		}
	}

	if (ve->fstubs_va.count == 0 && ve->vstubs_va.count == 0)
		fprintf(stderr, "No .vitalink sections found, continue");

	if (ve->symtab == NULL)
		DIE("No symbol table in binary, perhaps stripped out");

	if (ve->rela_tables == NULL)
		DIE("No relocation sections in binary; use -Wl,-q while compiling");

	if (ve->fstubs_va.count != 0) {
		if (!lookup_stub_symbols(ve, ve->num_fstubs, ve->fstubs, &ve->fstubs_va, STT_FUNC))
			goto failure;
	}

	if (ve->vstubs_va.count != 0) {
		if (!lookup_stub_symbols(ve, ve->num_vstubs, ve->vstubs, &ve->vstubs_va, STT_OBJECT))
			goto failure;
	}

	ELF_ASSERT(elf_getphdrnum(ve->elf, &segment_count) == 0);

	ve->segments = calloc(segment_count, sizeof(velf_segment_info_t));
	ASSERT(ve->segments != NULL);
	loaded_segments = 0;

	for (segndx = 0; segndx < segment_count; segndx++) {
		ELF_ASSERT(gelf_getphdr(ve->elf, segndx, &phdr));

		if (phdr.p_type != PT_LOAD) {
			continue; // skip non-loadable segments
		}

		curseg        = ve->segments + loaded_segments;
		curseg->type  = phdr.p_type;
		curseg->vaddr = phdr.p_vaddr;
		curseg->memsz = phdr.p_memsz;

		if (curseg->memsz) {
			curseg->vaddr_top = malloc(curseg->memsz);
			if (curseg->vaddr_top == NULL) {
				DIE("Could not allocate address space for segment %d", (int)segndx);
			}
			curseg->vaddr_bottom = curseg->vaddr_top + curseg->memsz;
		}

		loaded_segments++;
	}
	ve->num_segments = loaded_segments;

	return -1;

failure:
	return 0;
}

static void free_rela_table(velf_rela_table_t* rtable) {
	if (rtable == NULL)
		return;
	free(rtable->relas);
	free_rela_table(rtable->next);
	free(rtable);
}
vita_imports_stub_t* vita_imports_stub_new(const char* name, uint32_t nid) {
	vita_imports_stub_t* stub = malloc(sizeof(*stub));
	if (stub == NULL)
		return NULL;

	stub->name = strdup(name);
	stub->nid  = nid;

	return stub;
}

int velf_lookup_imports(velf_t* ve) {
	for (velf_stub_t* stub = ve->fstubs; stub < ve->fstubs + ve->num_fstubs; stub++) {
		stub->target = vita_imports_stub_new(stub->symbol ? stub->symbol->name : "(unreferenced stub)", 0);
	}
	for (velf_stub_t* stub = ve->vstubs; stub < ve->vstubs + ve->num_vstubs; stub++) {
		stub->target = vita_imports_stub_new(stub->symbol ? stub->symbol->name : "(unreferenced stub)", 0);
	}
	return 1;
}

const void* velf_vaddr_to_host(const velf_t* ve, Elf32_Addr vaddr) {
	velf_segment_info_t* seg;
	int                  i;

	for (i = 0, seg = ve->segments; i < ve->num_segments; i++, seg++) {
		if (vaddr >= seg->vaddr && vaddr < seg->vaddr + seg->memsz)
			return seg->vaddr_top + vaddr - seg->vaddr;
	}

	return NULL;
}
const void* velf_segoffset_to_host(const velf_t* ve, int segndx, uint32_t offset) {
	velf_segment_info_t* seg = ve->segments + segndx;

	if (offset < seg->memsz)
		return seg->vaddr_top + offset;

	return NULL;
}

Elf32_Addr velf_host_to_vaddr(const velf_t* ve, const void* host_addr) {
	velf_segment_info_t* seg;
	int                  i;

	if (host_addr == NULL)
		return 0;

	for (i = 0, seg = ve->segments; i < ve->num_segments; i++, seg++) {
		if (host_addr >= seg->vaddr_top && host_addr < seg->vaddr_bottom)
			return seg->vaddr + (uint32_t)(host_addr - seg->vaddr_top);
	}

	return 0;
}

int velf_host_to_segndx(const velf_t* ve, const void* host_addr) {
	velf_segment_info_t* seg;
	int                  i;

	for (i = 0, seg = ve->segments; i < ve->num_segments; i++, seg++) {
		if (host_addr >= seg->vaddr_top && host_addr < seg->vaddr_bottom)
			return i;
	}

	return -1;
}

int32_t velf_host_to_segoffset(const velf_t* ve, const void* host_addr, int segndx) {
	velf_segment_info_t* seg = ve->segments + segndx;

	if (host_addr == NULL)
		return 0;

	if (host_addr >= seg->vaddr_top && host_addr < seg->vaddr_bottom)
		return (uint32_t)(host_addr - seg->vaddr_top);

	return -1;
}

int velf_vaddr_to_segndx(const velf_t* ve, Elf32_Addr vaddr) {
	velf_segment_info_t* seg;
	int                  i;

	for (i = 0, seg = ve->segments; i < ve->num_segments; i++, seg++) {
		/* Segments of type EXIDX will duplicate '.ARM.extab .ARM.exidx' sections already present in the data segment
		 * Since these won't be loaded, we should prefer the actual data segment */
		if (seg->type == SHT_ARM_EXIDX)
			continue;
		if (vaddr >= seg->vaddr && vaddr < seg->vaddr + seg->memsz)
			return i;
	}

	return -1;
}

/* velf_vaddr_to_segoffset won't check the validity of the address, it may have been fuzzy-matched */
uint32_t velf_vaddr_to_segoffset(const velf_t* ve, Elf32_Addr vaddr, int segndx) {
	velf_segment_info_t* seg = ve->segments + segndx;

	if (vaddr == 0)
		return 0;

	return vaddr - seg->vaddr;
}

const uint32_t sce_elf_stub_func[3] = {
    0xe3e00000, /* mvn r0, #0 */
    0xe12fff1e, /* bx lr */
    0xe1a00000  /* mov r0, r0 */
};

#define ALIGN_4(size) (((size) + 3) & ~0x3)

typedef struct {
	uint32_t            nid;
	vita_imports_lib_t* library;

	union {
		velf_stub_t* functions;
		varray       functions_va;
	};

	union {
		velf_stub_t* variables;
		varray       variables_va;
	};
} import_library;

static int _stub_sort(const void* el1, const void* el2) {
	const velf_stub_t *stub1 = el1, *stub2 = el2;
	if (stub2->target_nid > stub1->target_nid)
		return 1;
	else if (stub2->target_nid < stub1->target_nid)
		return -1;
	return 0;
}
static int _stub_nid_search(const void* key, const void* element) {
	const uint32_t*    nid  = key;
	const velf_stub_t* stub = element;
	if (stub->target_nid > *nid)
		return 1;
	else if (stub->target_nid < *nid)
		return -1;
	return 0;
}

static void* _module_init(void* element) {
	import_library* library = element;
	if (!varray_init(&library->functions_va, sizeof(velf_stub_t), 8))
		return NULL;
	if (!varray_init(&library->variables_va, sizeof(velf_stub_t), 4))
		return NULL;

	library->functions_va.sort_compar   = _stub_sort;
	library->functions_va.search_compar = _stub_nid_search;
	library->variables_va.sort_compar   = _stub_sort;
	library->variables_va.search_compar = _stub_nid_search;

	return library;
}
static void _module_destroy(void* element) {
	import_library* library = element;
	varray_destroy(&library->functions_va);
	varray_destroy(&library->variables_va);
}

static int _module_sort(const void* el1, const void* el2) {
	const import_library *lib1 = el1, *lib2 = el2;
	if (lib2->nid > lib1->nid)
		return 1;
	else if (lib2->nid < lib1->nid)
		return -1;
	return 0;
}

static int _module_search(const void* key, const void* element) {
	const uint32_t*       nid     = key;
	const import_library* library = element;
	if (library->nid > *nid)
		return 1;
	else if (library->nid < *nid)
		return -1;
	return 0;
}

static int get_function_by_symbol(const char* symbol, const velf_t* ve, Elf32_Addr* vaddr) {
	int i;

	for (i = 0; i < ve->num_symbols; ++i) {
		if (ve->symtab[i].type != STT_FUNC)
			continue;

		if (strcmp(ve->symtab[i].name, symbol) == 0) {
			*vaddr = ve->symtab[i].value;
			break;
		}
	}

	return i != ve->num_symbols;
}

int get_variable_by_symbol(const char* symbol, const velf_t* ve, Elf32_Addr* vaddr) {
	int i;

	for (i = 0; i < ve->num_symbols; ++i) {
		if (ve->symtab[i].type != STT_OBJECT)
			continue;

		if (strcmp(ve->symtab[i].name, symbol) == 0) {
			*vaddr = ve->symtab[i].value;
			break;
		}
	}

	return i != ve->num_symbols;
}

typedef union {
	import_library* libs;
	varray          va;
} import_library_list;

static int set_module_export(velf_t* ve, sce_module_exports_t* export, vita_library_export* lib) {
	export->size           = sizeof(sce_module_exports_raw);
	export->version        = lib->version;
	export->flags          = lib->syscall ? 0x4001 : 0x0001;
	export->num_syms_funcs = lib->function_n;
	export->num_syms_vars  = lib->variable_n;
	export->library_name   = strdup(lib->name);
	export->library_nid    = lib->nid;

	int total_exports   = export->num_syms_funcs + export->num_syms_vars;
	export->nid_table   = calloc(total_exports, sizeof(uint32_t));
	export->entry_table = calloc(total_exports, sizeof(void*));

	int cur_ent = 0;
	int i;
	for (i = 0; i < export->num_syms_funcs; ++i) {
		Elf32_Addr          vaddr = 0;
		vita_export_symbol* sym   = lib->functions[i];

		if (!get_function_by_symbol(sym->name, ve, &vaddr)) {
			DIE("Could not find function symbol '%s' for export '%s'", sym->name, lib->name);
		}

		export->nid_table[cur_ent]   = sym->nid;
		export->entry_table[cur_ent] = velf_vaddr_to_host(ve, vaddr);
		++cur_ent;
	}

	for (i = 0; i < export->num_syms_vars; ++i) {
		Elf32_Addr          vaddr = 0;
		vita_export_symbol* sym   = lib->variables[i];

		if (!get_variable_by_symbol(sym->name, ve, &vaddr)) {
			DIE("Could not find variable symbol '%s' for export '%s'", sym->name, lib->name);
		}

		export->nid_table[cur_ent]   = sym->nid;
		export->entry_table[cur_ent] = velf_vaddr_to_host(ve, vaddr);
		++cur_ent;
	}

	return 0;

failure:
	return -1;
}

static int set_main_module_export(velf_t* ve, sce_module_exports_t* export, sce_modinfo_t* modinfo, vita_export_t* export_spec,
                                  sce_process_param_t* process_param) {
	export->size           = sizeof(sce_module_exports_raw);
	export->version        = 0;
	export->flags          = 0x8000;
	export->num_syms_funcs = export_spec->is_image_module ? 0 : 1;
	export->num_syms_vars  = 3; // module_info + process_param + sdk_version

	if (!export_spec->is_image_module) {
		export->num_syms_funcs += !!export_spec->bootstart + !!export_spec->stop + !!export_spec->exit;
	}

	int total_exports   = export->num_syms_funcs + export->num_syms_vars;
	export->nid_table   = calloc(total_exports, sizeof(*export->nid_table));
	export->entry_table = calloc(total_exports, sizeof(*export->entry_table));

	int cur_nid = 0;
	if (!export_spec->is_image_module) {
		if (export_spec->start) {
			Elf32_Addr vaddr = 0;
			if (!get_function_by_symbol(export_spec->start, ve, &vaddr)) {
				DIE("Could not find symbol '%s' for main export 'start'", export_spec->start);
			}

			modinfo->module_start = velf_vaddr_to_host(ve, vaddr);
		} else {
			modinfo->module_start = velf_vaddr_to_host(ve, elf32_getehdr(ve->elf)->e_entry);
		}

		export->nid_table[cur_nid]   = NID_MODULE_START;
		export->entry_table[cur_nid] = modinfo->module_start;
		++cur_nid;

		if (export_spec->bootstart) {
			Elf32_Addr vaddr = 0;

			if (!get_function_by_symbol(export_spec->bootstart, ve, &vaddr)) {
				DIE("Could not find symbol '%s' for main export 'bootstart'", export_spec->bootstart);
			}

			export->nid_table[cur_nid]   = NID_MODULE_BOOTSTART;
			export->entry_table[cur_nid] = velf_vaddr_to_host(ve, vaddr);
			++cur_nid;
		}

		if (export_spec->stop) {
			Elf32_Addr vaddr = 0;

			if (!get_function_by_symbol(export_spec->stop, ve, &vaddr)) {
				DIE("Could not find symbol '%s' for main export 'stop'", export_spec->stop);
			}

			export->nid_table[cur_nid]   = NID_MODULE_STOP;
			export->entry_table[cur_nid] = modinfo->module_stop = velf_vaddr_to_host(ve, vaddr);
			++cur_nid;
		}

		if (export_spec->exit) {
			Elf32_Addr vaddr = 0;

			if (!get_function_by_symbol(export_spec->exit, ve, &vaddr)) {
				DIE("Could not find symbol '%s' for main export 'exit'", export_spec->exit);
			}

			export->nid_table[cur_nid]   = NID_MODULE_EXIT;
			export->entry_table[cur_nid] = velf_vaddr_to_host(ve, vaddr);
			++cur_nid;
		}
	}

	export->nid_table[cur_nid]   = NID_MODULE_INFO;
	export->entry_table[cur_nid] = modinfo;
	++cur_nid;

	export->nid_table[cur_nid]   = NID_PROCESS_PARAM;
	export->entry_table[cur_nid] = process_param;
	++cur_nid;

	export->nid_table[cur_nid]   = NID_MODULE_SDK_VERSION;
	export->entry_table[cur_nid] = &modinfo->module_sdk_version;
	++cur_nid;

	return 0;

failure:
	return -1;
}

static void set_module_import(velf_t* ve, sce_module_imports_t* import, const import_library* library) {
	int i;

	import->size = sizeof(sce_module_imports_raw);

	if (((library->library->flags >> 16) & 0xFFFF) <= 1) {
		import->version = 1;
	} else {
		import->version = ((library->library->flags >> 16) & 0xFFFF);
	}
	import->num_syms_funcs = library->functions_va.count;
	import->num_syms_vars  = library->variables_va.count;
	import->library_nid    = library->nid;
	import->flags          = library->library->flags & 0xFFFF;

	if (library->library) {
		import->library_name = library->library->name;
	}

	import->func_nid_table   = calloc(library->functions_va.count, sizeof(uint32_t));
	import->func_entry_table = calloc(library->functions_va.count, sizeof(void*));
	for (i = 0; i < library->functions_va.count; i++) {
		import->func_nid_table[i]   = library->functions[i].target_nid;
		import->func_entry_table[i] = velf_vaddr_to_host(ve, library->functions[i].addr);
	}

	import->var_nid_table   = calloc(library->variables_va.count, sizeof(uint32_t));
	import->var_entry_table = calloc(library->variables_va.count, sizeof(void*));
	for (i = 0; i < library->variables_va.count; i++) {
		import->var_nid_table[i]   = library->variables[i].target_nid;
		import->var_entry_table[i] = velf_vaddr_to_host(ve, library->variables[i].addr);
	}
}

void velf_modinfo_free(sce_modinfo_t* modinfo) {
	sce_module_exports_t* export;
	sce_module_imports_t* import;

	if (modinfo == NULL)
		return;

	for (export = modinfo->export_top; export < modinfo->export_end; export ++) {
		free(export->nid_table);
		free(export->entry_table);
	}
	free(modinfo->export_top);

	for (import = modinfo->import_top; import < modinfo->import_end; import++) {
		free(import->func_nid_table);
		free(import->func_entry_table);
		free(import->var_nid_table);
		free(import->var_entry_table);
		free(import->tls_var_nid_table);
		free(import->tls_var_entry_table);
	}

	free(modinfo->import_top);
}
sce_modinfo_t* velf_modinfo_create(velf_t* ve, sce_modinfo_t* modinfo, vita_export_t* exports, sce_process_param_t* process_param) {
	int                 i;
	import_library_list liblist = {0};
	velf_stub_t*        curstub;
	import_library*     curlib;

	modinfo->type               = 6;
	modinfo->version            = (exports->ver_major << 8) | exports->ver_minor;
	modinfo->module_sdk_version = PSP2_SDK_VERSION;

	strncpy(modinfo->name, exports->name, sizeof(modinfo->name) - 1);

	// allocate memory for all libraries + main
	modinfo->export_top = calloc(exports->lib_n + 1, sizeof(sce_module_exports_t));
	ASSERT(modinfo->export_top != NULL);
	modinfo->export_end = modinfo->export_top + exports->lib_n + 1;

	if (set_main_module_export(ve, modinfo->export_top, modinfo, exports, process_param) < 0) {
		goto sce_failure;
	}

	// populate rest of exports
	for (i = 0; i < exports->lib_n; ++i) {
		vita_library_export*  lib = exports->libs[i];
		sce_module_exports_t* exp = (sce_module_exports_t*)(modinfo->export_top + i + 1);

		// TODO: improve cleanup
		if (set_module_export(ve, exp, lib) < 0) {
			goto sce_failure;
		}
	}

	ASSERT(varray_init(&liblist.va, sizeof(import_library), 8));
	liblist.va.init_func     = _module_init;
	liblist.va.destroy_func  = _module_destroy;
	liblist.va.sort_compar   = _module_sort;
	liblist.va.search_compar = _module_search;

	for (i = 0; i < ve->num_fstubs; i++) {
		curstub = ve->fstubs + i;
		curlib  = varray_sorted_search_or_insert(&liblist.va, &curstub->library_nid, NULL);
		ASSERT(curlib);
		curlib->nid = curstub->library_nid;
		if (curstub->library)
			curlib->library = curstub->library;

		varray_sorted_insert_ex(&curlib->functions_va, curstub, 0);
	}

	for (i = 0; i < ve->num_vstubs; i++) {
		curstub = ve->vstubs + i;
		curlib  = varray_sorted_search_or_insert(&liblist.va, &curstub->library_nid, NULL);
		ASSERT(curlib);
		curlib->nid = curstub[i].library_nid;
		if (curstub[i].library)
			curlib->library = curstub[i].library;

		varray_sorted_insert_ex(&curlib->variables_va, curstub, 0);
	}

	modinfo->import_top = calloc(liblist.va.count, sizeof(sce_module_imports_t));
	ASSERT(modinfo->import_top != NULL);
	modinfo->import_end = modinfo->import_top + liblist.va.count;

	for (i = 0; i < liblist.va.count; i++) {
		set_module_import(ve, modinfo->import_top + i, liblist.libs + i);
	}

	return modinfo;

failure:
	varray_destroy(&liblist.va);

sce_failure:
	velf_modinfo_free(modinfo);
	return NULL;
}

int velf_modinfo_sum_size(const sce_section_sizes_t* sec_sizes) {
	Elf32_Word* section_sizes = (Elf32_Word*)sec_sizes;
	size_t      section_count = sizeof(*sec_sizes) / sizeof(*section_sizes);
	size_t      total_size    = 0;
	for (Elf32_Word* size = section_sizes; size < section_sizes + section_count; size++) {
		total_size += *size;
	}
	return total_size;
}
void velf_modinfo_compute_size(sce_modinfo_t* modinfo, sce_section_sizes_t* sizes, int have_libc) {
	sizes->sceModuleInfo_rodata += sizeof(sce_modinfo_raw);
	sizes->sceModuleInfo_rodata += sizeof(sce_process_param_raw);
	sizes->sceModuleInfo_rodata += (have_libc ? sizeof(sce_param_libc_raw) : 0);

	for (sce_module_exports_t* export = modinfo->export_top; export < modinfo->export_end; export ++) {
		sizes->sceLib_ent += sizeof(sce_module_exports_raw);
		if (export->library_name != NULL) {
			sizes->sceExport_rodata += ALIGN_4(strlen(export->library_name) + 1);
		}
		sizes->sceExport_rodata += (export->num_syms_funcs + export->num_syms_vars + export->num_syms_tls_vars) * 8;
	}

	for (sce_module_imports_t* import = modinfo->import_top; import < modinfo->import_end; import++) {
		sizes->sceLib_stubs += sizeof(sce_module_imports_raw);
		if (import->library_name != NULL) {
			sizes->sceImport_rodata += ALIGN_4(strlen(import->library_name) + 1);
		}
		sizes->sceFNID_rodata += import->num_syms_funcs * sizeof(uint32_t);
		sizes->sceFStub_rodata += import->num_syms_funcs * sizeof(Elf32_Addr);
		sizes->sceVNID_rodata += import->num_syms_vars * sizeof(uint32_t);
		sizes->sceVStub_rodata += import->num_syms_vars * sizeof(Elf32_Addr);
		sizes->sceImport_rodata += import->num_syms_tls_vars * 8;
	}
}

#define INCR(section, size)                              \
	do {                                                   \
		sec_siz.section += (size);                           \
		if (sec_siz.section > sizes->section)                \
			DIE("Attempted to overrun section %s!", #section); \
		sec_off.section += (size);                           \
	} while (0)
#define ADDR(section)                         (data + sec_off.section)
#define INTADDR(section)                      (*((uint32_t*)ADDR(section)))
#define VADDR(section)                        (sec_off.section + segment_base + start_offset)
#define OFFSET(section)                       (sec_off.section + start_offset)
#define CONVERT(variable, member, conversion) variable##_raw->member = conversion(variable->member)
#define CONVERT16(variable, member)           CONVERT(variable, member, htole16)
#define CONVERT32(variable, member)           CONVERT(variable, member, htole32)
#define CONVERTOFFSET(variable, member)       variable##_raw->member = htole32(velf_host_to_segoffset(ve, variable->member, segndx))
#define SETLOCALPTR(variable, section)  \
	do {                                  \
		variable = htole32(VADDR(section)); \
		ADDRELA(&variable);                 \
	} while (0)
#define ADDRELA(localaddr)                                                           \
	do {                                                                               \
		uint32_t addend = le32toh(*((uint32_t*)localaddr));                              \
		if (addend) {                                                                    \
			velf_rela_t* rela = varray_push(&relas, NULL);                                 \
			rela->type        = R_ARM_ABS32;                                               \
			rela->offset      = ((void*)(localaddr)) - data + segment_base + start_offset; \
			rela->addend      = addend;                                                    \
		}                                                                                \
	} while (0)

void* velf_modinfo_encode(sce_modinfo_t* modinfo, velf_t* ve, sce_section_sizes_t* sizes, velf_rela_table_t* rtable, sce_process_param_t* process_param,
                          sce_param_libc_t* libc_param, void* data) {
	sce_section_sizes_t sec_off   = {0};
	Elf32_Word*         sizes_int = (Elf32_Word*)sizes;
	Elf32_Word*         addrs_int = (Elf32_Word*)&sec_off;
	for (int i = 0, acc = 0; i < sizeof(*sizes) / sizeof(*sizes_int); i++) {
		addrs_int[i] = acc;
		acc += sizes_int[i];
	}

	int segndx = modinfo->module_start ? velf_host_to_segndx(ve, modinfo->module_start) : 0;

	Elf32_Addr segment_base = ve->segments[segndx].vaddr;
	Elf32_Word start_offset = (ve->segments[segndx].memsz + 0xF) & ~0xF; // align to 16 bytes

	int total_size = velf_modinfo_sum_size(sizes);
	for (int i = 0; i < ve->num_segments; i++) {
		if (i == segndx)
			continue;
		if (ve->segments[i].vaddr >= segment_base + start_offset && ve->segments[i].vaddr < segment_base + start_offset + total_size)
			DIE("Cannot allocate %d bytes for SCE data at end of segment %d; segment %d overlaps", total_size, segndx, i);
	}

	varray relas;
	ASSERT(varray_init(&relas, sizeof(velf_rela_t), 16));

	uint32_t process_param_offset = sizeof(sce_modinfo_raw);
	uint32_t libc_param_offset    = process_param_offset + sizeof(sce_process_param_raw);
	if (libc_param) {
		sce_param_libc_raw* libc_param_raw = (sce_param_libc_raw*)(ADDR(sceModuleInfo_rodata) + libc_param_offset);
		{ // sce_libc_general
			CONVERT32(libc_param, sce_libc_general.size);
			CONVERT32(libc_param, sce_libc_general.fw_version);
			CONVERT32(libc_param, sce_libc_general.unk_0x1C);
			CONVERT32(libc_param, _default_heap_size);
			libc_param_raw->sce_libc_general.default_heap_size = VADDR(sceModuleInfo_rodata) + libc_param_offset + offsetof(sce_param_libc_raw, _default_heap_size);
			get_variable_by_symbol("sceLibcHeapSize", ve, &libc_param_raw->sce_libc_general.heap_size);
			libc_param_raw->sce_libc_general.malloc_replace = VADDR(sceModuleInfo_rodata) + libc_param_offset + offsetof(sce_param_libc_raw, sce_libc_hook_alloc);
			libc_param_raw->sce_libc_general.new_replace    = VADDR(sceModuleInfo_rodata) + libc_param_offset + offsetof(sce_param_libc_raw, sce_libc_hook_new);
			libc_param_raw->sce_libc_general.malloc_for_tls_replace =
			    VADDR(sceModuleInfo_rodata) + libc_param_offset + offsetof(sce_param_libc_raw, sce_libc_hook_tls);
			ADDRELA(&libc_param_raw->sce_libc_general.default_heap_size);
			ADDRELA(&libc_param_raw->sce_libc_general.heap_size);
			ADDRELA(&libc_param_raw->sce_libc_general.malloc_replace);
			ADDRELA(&libc_param_raw->sce_libc_general.new_replace);
			ADDRELA(&libc_param_raw->sce_libc_general.malloc_for_tls_replace);
		}
		{ // sce_libc_hook_alloc
			// Memory allocation function names were found here: https://github.com/Olde-Skuul/burgerlib/blob/master/source/vita/brvitamemory.h
			// Credit to Rebecca Ann Heineman <becky@burgerbecky.com>
			libc_param_raw->sce_libc_hook_alloc.size    = sizeof(libc_param_raw->sce_libc_hook_alloc);
			libc_param_raw->sce_libc_hook_alloc.unk_0x4 = 1;
			get_function_by_symbol("user_malloc_init", ve, &libc_param_raw->sce_libc_hook_alloc.malloc_init);
			get_function_by_symbol("user_malloc_finalize", ve, &libc_param_raw->sce_libc_hook_alloc.malloc_term);
			get_function_by_symbol("user_malloc", ve, &libc_param_raw->sce_libc_hook_alloc.malloc);
			get_function_by_symbol("user_free", ve, &libc_param_raw->sce_libc_hook_alloc.free);
			get_function_by_symbol("user_calloc", ve, &libc_param_raw->sce_libc_hook_alloc.calloc);
			get_function_by_symbol("user_realloc", ve, &libc_param_raw->sce_libc_hook_alloc.realloc);
			get_function_by_symbol("user_memalign", ve, &libc_param_raw->sce_libc_hook_alloc.memalign);
			get_function_by_symbol("user_reallocalign", ve, &libc_param_raw->sce_libc_hook_alloc.reallocalign);
			get_function_by_symbol("user_malloc_stats", ve, &libc_param_raw->sce_libc_hook_alloc.malloc_stats);
			get_function_by_symbol("user_malloc_stats_fast", ve, &libc_param_raw->sce_libc_hook_alloc.malloc_stats_fast);
			get_function_by_symbol("user_malloc_usable_size", ve, &libc_param_raw->sce_libc_hook_alloc.malloc_usable_size);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.malloc_init);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.malloc_term);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.malloc);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.free);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.calloc);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.realloc);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.memalign);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.reallocalign);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.malloc_stats);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.malloc_stats_fast);
			ADDRELA(&libc_param_raw->sce_libc_hook_alloc.malloc_usable_size);
		}
		{ // sce_libc_hook_tls
			libc_param_raw->sce_libc_hook_tls.size    = sizeof(libc_param_raw->sce_libc_hook_tls);
			libc_param_raw->sce_libc_hook_tls.unk_0x4 = 0x1;
			get_function_by_symbol("user_malloc_for_tls_init", ve, &libc_param_raw->sce_libc_hook_tls.malloc_init_for_tls);
			get_function_by_symbol("user_malloc_for_tls_finalize", ve, &libc_param_raw->sce_libc_hook_tls.malloc_term_for_tls);
			get_function_by_symbol("user_malloc_for_tls", ve, &libc_param_raw->sce_libc_hook_tls.malloc_for_tls);
			get_function_by_symbol("user_free_for_tls", ve, &libc_param_raw->sce_libc_hook_tls.free_for_tls);
			ADDRELA(&libc_param_raw->sce_libc_hook_tls.malloc_init_for_tls);
			ADDRELA(&libc_param_raw->sce_libc_hook_tls.malloc_term_for_tls);
			ADDRELA(&libc_param_raw->sce_libc_hook_tls.malloc_for_tls);
			ADDRELA(&libc_param_raw->sce_libc_hook_tls.free_for_tls);
		}
		{ // sce_libc_hook_new
			libc_param_raw->sce_libc_hook_new.size    = sizeof(libc_param_raw->sce_libc_hook_new);
			libc_param_raw->sce_libc_hook_new.unk_0x4 = 1;
			// user_new(std::size_t) throw(std::badalloc)
			get_function_by_symbol("_Z8user_newj", ve, &libc_param_raw->sce_libc_hook_new.operator_new);
			// user_new(std::size_t, std::nothrow_t const&)
			get_function_by_symbol("_Z8user_newjRKSt9nothrow_t", ve, &libc_param_raw->sce_libc_hook_new.operator_new_nothrow);
			// user_new_array(std::size_t) throw(std::badalloc)
			get_function_by_symbol("_Z14user_new_arrayj", ve, &libc_param_raw->sce_libc_hook_new.operator_new_arr);
			// user_new_array(std::size_t, std::nothrow_t const&)
			get_function_by_symbol("_Z14user_new_arrayjRKSt9nothrow_t", ve, &libc_param_raw->sce_libc_hook_new.operator_new_arr_nothrow);
			// user_delete(void*)
			get_function_by_symbol("_Z11user_deletePv", ve, &libc_param_raw->sce_libc_hook_new.operator_delete);
			// user_delete(void*, std::nothrow_t const&)
			get_function_by_symbol("_Z11user_deletePvRKSt9nothrow_t", ve, &libc_param_raw->sce_libc_hook_new.operator_delete_nothrow);
			// user_delete_array(void*)
			get_function_by_symbol("_Z17user_delete_arrayPv", ve, &libc_param_raw->sce_libc_hook_new.operator_delete_arr);
			// user_delete_array(void*, std::nothrow_t const&)
			get_function_by_symbol("_Z17user_delete_arrayPvRKSt9nothrow_t", ve, &libc_param_raw->sce_libc_hook_new.operator_delete_arr_nothrow);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_new);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_new_nothrow);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_new_arr);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_new_arr_nothrow);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_delete);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_delete_nothrow);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_delete_arr);
			ADDRELA(&libc_param_raw->sce_libc_hook_new.operator_delete_arr_nothrow);
		}
	}

	sce_process_param_raw* process_param_raw = (sce_process_param_raw*)(ADDR(sceModuleInfo_rodata) + process_param_offset);
	CONVERT32(process_param, size);
	CONVERT32(process_param, magic);
	CONVERT32(process_param, version);
	CONVERT32(process_param, fw_version);
	get_variable_by_symbol("sceUserMainThreadName", ve, &process_param_raw->main_thread_name);
	get_variable_by_symbol("sceUserMainThreadPriority", ve, (uint32_t*)&process_param_raw->main_thread_priority);
	get_variable_by_symbol("sceUserMainThreadStackSize", ve, &process_param_raw->main_thread_stacksize);
	get_variable_by_symbol("sceUserMainThreadCpuAffinityMask", ve, &process_param_raw->main_thread_cpu_affinity_mask);
	get_variable_by_symbol("sceUserMainThreadAttribute", ve, &process_param_raw->main_thread_attribute);
	get_variable_by_symbol("sceKernelPreloadModuleInhibit", ve, &process_param_raw->process_preload_disabled);
	ADDRELA(&process_param_raw->main_thread_name);
	ADDRELA(&process_param_raw->main_thread_priority);
	ADDRELA(&process_param_raw->main_thread_stacksize);
	ADDRELA(&process_param_raw->main_thread_cpu_affinity_mask);
	ADDRELA(&process_param_raw->main_thread_attribute);
	ADDRELA(&process_param_raw->process_preload_disabled);
	if (libc_param != NULL) {
		process_param_raw->sce_param_libc = VADDR(sceModuleInfo_rodata) + libc_param_offset + offsetof(sce_param_libc_raw, sce_libc_general.size);
		ADDRELA(&process_param_raw->sce_param_libc);
	}

	sce_modinfo_raw* modinfo_raw = (sce_modinfo_raw*)ADDR(sceModuleInfo_rodata);
	CONVERT16(modinfo, attributes);
	CONVERT16(modinfo, version);
	memcpy(modinfo_raw->name, modinfo->name, sizeof(modinfo->name));
	modinfo_raw->type       = modinfo->type;
	modinfo_raw->export_top = htole32(OFFSET(sceLib_ent));
	modinfo_raw->export_end = htole32(OFFSET(sceLib_ent) + sizes->sceLib_ent);
	modinfo_raw->import_top = htole32(OFFSET(sceLib_stubs));
	modinfo_raw->import_end = htole32(OFFSET(sceLib_stubs) + sizes->sceLib_stubs);
	CONVERT32(modinfo, module_nid);
	CONVERT32(modinfo, tls_start);
	CONVERT32(modinfo, tls_filesz);
	CONVERT32(modinfo, tls_memsz);
	if (modinfo->module_start != NULL) {
		CONVERTOFFSET(modinfo, module_start);
	} else {
		modinfo_raw->module_start = 0xFFFFFFFF;
		modinfo_raw->import_top   = 0;
		modinfo_raw->import_end   = 0;
	}
	if (modinfo->module_stop != NULL) {
		CONVERTOFFSET(modinfo, module_stop);
	} else {
		modinfo_raw->module_stop = 0xFFFFFFFF;
	}
	CONVERTOFFSET(modinfo, exidx_top);
	CONVERTOFFSET(modinfo, exidx_end);
	CONVERTOFFSET(modinfo, extab_top);
	CONVERTOFFSET(modinfo, extab_end);
	CONVERT32(modinfo, module_sdk_version);

	sce_section_sizes_t sec_siz = {0};
	for (sce_module_exports_t* export = modinfo->export_top; export < modinfo->export_end; export ++) {
		int       num_syms;
		uint32_t *raw_nids, *raw_entries;

		sce_module_exports_raw* export_raw = (sce_module_exports_raw*)ADDR(sceLib_ent);
		INCR(sceLib_ent, sizeof(sce_module_exports_raw));

		export_raw->size = htole16(sizeof(sce_module_exports_raw));
		CONVERT16(export, version);
		CONVERT16(export, flags);
		CONVERT16(export, num_syms_funcs);
		CONVERT32(export, num_syms_vars);
		CONVERT32(export, num_syms_tls_vars);
		CONVERT32(export, library_nid);
		if (export->library_name != NULL) {
			SETLOCALPTR(export_raw->library_name, sceExport_rodata);
			void* dst = ADDR(sceExport_rodata);
			INCR(sceExport_rodata, ALIGN_4(strlen(export->library_name) + 1));
			strcpy(dst, export->library_name);
		}
		num_syms = export->num_syms_funcs + export->num_syms_vars + export->num_syms_tls_vars;
		SETLOCALPTR(export_raw->nid_table, sceExport_rodata);
		raw_nids = (uint32_t*)ADDR(sceExport_rodata);
		INCR(sceExport_rodata, num_syms * 4);
		SETLOCALPTR(export_raw->entry_table, sceExport_rodata);
		raw_entries = (uint32_t*)ADDR(sceExport_rodata);
		INCR(sceExport_rodata, num_syms * 4);
		for (int i = 0; i < num_syms; i++) {
			raw_nids[i] = htole32(export->nid_table[i]);
			if (export->entry_table[i] == modinfo) { /* Special case */
				raw_entries[i] = htole32(segment_base + start_offset);
			} else if (export->entry_table[i] == process_param) {
				raw_entries[i] = htole32(VADDR(sceModuleInfo_rodata) + process_param_offset);
			} else if (export->entry_table[i] == &modinfo->module_sdk_version) {
				raw_entries[i] = htole32(VADDR(sceModuleInfo_rodata) + offsetof(sce_modinfo_raw, module_sdk_version));
			} else {
				raw_entries[i] = htole32(velf_host_to_vaddr(ve, export->entry_table[i]));
			}
			ADDRELA(raw_entries + i);
		}
	}

	for (sce_module_imports_t* import = modinfo->import_top; import < modinfo->import_end; import++) {
		sce_module_imports_raw* import_raw = (sce_module_imports_raw*)ADDR(sceLib_stubs);
		INCR(sceLib_stubs, sizeof(sce_module_imports_raw));

		import_raw->size = htole16(sizeof(sce_module_imports_raw));
		CONVERT16(import, version);
		CONVERT16(import, flags);
		CONVERT16(import, num_syms_funcs);
		CONVERT16(import, num_syms_vars);
		CONVERT16(import, num_syms_tls_vars);
		CONVERT32(import, reserved1);
		CONVERT32(import, reserved2);
		CONVERT32(import, library_nid);

		if (import->library_name != NULL) {
			SETLOCALPTR(import_raw->library_name, sceImport_rodata);
			void* dst = ADDR(sceImport_rodata);
			INCR(sceImport_rodata, ALIGN_4(strlen(import->library_name) + 1));
			strcpy(dst, import->library_name);
		}
		if (import->num_syms_funcs) {
			SETLOCALPTR(import_raw->func_nid_table, sceFNID_rodata);
			SETLOCALPTR(import_raw->func_entry_table, sceFStub_rodata);
			for (int i = 0; i < import->num_syms_funcs; i++) {
				INTADDR(sceFNID_rodata)  = htole32(import->func_nid_table[i]);
				INTADDR(sceFStub_rodata) = htole32(velf_host_to_vaddr(ve, import->func_entry_table[i]));
				ADDRELA(ADDR(sceFStub_rodata));
				INCR(sceFNID_rodata, 4);
				INCR(sceFStub_rodata, 4);
			}
		}
		if (import->num_syms_vars) {
			SETLOCALPTR(import_raw->var_nid_table, sceVNID_rodata);
			SETLOCALPTR(import_raw->var_entry_table, sceVStub_rodata);
			for (int i = 0; i < import->num_syms_vars; i++) {
				INTADDR(sceVNID_rodata)  = htole32(import->var_nid_table[i]);
				INTADDR(sceVStub_rodata) = htole32(velf_host_to_vaddr(ve, import->var_entry_table[i]));
				ADDRELA(ADDR(sceVStub_rodata));
				INCR(sceVNID_rodata, 4);
				INCR(sceVStub_rodata, 4);
			}
		}
		if (import->num_syms_tls_vars) {
			SETLOCALPTR(import_raw->tls_var_nid_table, sceImport_rodata);
			for (int i = 0; i < import->num_syms_tls_vars; i++) {
				INTADDR(sceImport_rodata) = htole32(import->var_nid_table[i]);
				INCR(sceImport_rodata, 4);
			}
			SETLOCALPTR(import_raw->tls_var_entry_table, sceImport_rodata);
			for (int i = 0; i < import->num_syms_tls_vars; i++) {
				INTADDR(sceImport_rodata) = htole32(velf_host_to_vaddr(ve, import->var_entry_table[i]));
				ADDRELA(ADDR(sceImport_rodata));
				INCR(sceImport_rodata, 4);
			}
		}
	}
	INCR(sceModuleInfo_rodata, sizeof(sce_modinfo_raw));
	INCR(sceModuleInfo_rodata, sizeof(sce_process_param_raw));
	INCR(sceModuleInfo_rodata, libc_param ? sizeof(sce_param_libc_raw) : 0);

	if (memcmp(sizes, &sec_siz, sizeof(sec_siz)))
		DIE("velf_modinfo_encode() did not use all space in section !");

	rtable->num_relas = relas.count;
	rtable->relas     = varray_extract_array(&relas);

	return data;
failure:
	return NULL;
}
#undef INCR
#undef ADDR
#undef INTADDR
#undef VADDR
#undef OFFSET
#undef CONVERT
#undef CONVERT16
#undef CONVERT32
#undef CONVERTOFFSET
#undef SETLOCALPTR
#undef ADDRELA

int elf_utils_shift_contents(Elf* e, int start_offset, int shift_amount) {
	GElf_Ehdr  ehdr;
	Elf_Scn*   scn;
	GElf_Shdr  shdr;
	size_t     segment_count = 0, segndx;
	GElf_Phdr  phdr;
	int        bottom_section_offset = 0;
	GElf_Xword sh_size;

	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	if (ehdr.e_shoff >= start_offset) {
		ehdr.e_shoff += shift_amount;
		ELF_ASSERT(gelf_update_ehdr(e, &ehdr));
	}

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		ELF_ASSERT(gelf_getshdr(scn, &shdr));
		if (shdr.sh_offset >= start_offset) {
			shdr.sh_offset += shift_amount;
			ELF_ASSERT(gelf_update_shdr(scn, &shdr));
		}
		sh_size = (shdr.sh_type == SHT_NOBITS) ? 0 : shdr.sh_size;
		if (shdr.sh_offset + sh_size > bottom_section_offset) {
			bottom_section_offset = shdr.sh_offset + sh_size;
		}
	}

	if (bottom_section_offset > ehdr.e_shoff) {
		ELF_ASSERT(gelf_getehdr(e, &ehdr));
		ehdr.e_shoff = bottom_section_offset;
		ELF_ASSERT(gelf_update_ehdr(e, &ehdr));
	}

	/* A bug in libelf means that getphdrnum will report failure in a new file.
	 * However, it will still set segment_count, so we'll use it. */
	ELF_ASSERT((elf_getphdrnum(e, &segment_count), segment_count > 0));

	for (segndx = 0; segndx < segment_count; segndx++) {
		ELF_ASSERT(gelf_getphdr(e, segndx, &phdr));
		if (phdr.p_offset >= start_offset) {
			phdr.p_offset += shift_amount;
			ELF_ASSERT(gelf_update_phdr(e, segndx, &phdr));
		}
	}

	return 1;
failure:
	return 0;
}
Elf_Scn* elf_utils_new_scn_with_name(Elf* e, const char* scn_name) {
	Elf_Scn*  scn;
	GElf_Shdr shdr;
	size_t    shstrndx, index, namelen;
	Elf_Data* shstrdata;
	void*     ptr;

	ELF_ASSERT(!elf_getshdrstrndx(e, &shstrndx));
	ELF_ASSERT(scn = elf_getscn(e, shstrndx));
	ELF_ASSERT(shstrdata = elf_getdata(scn, NULL));

	namelen = strlen(scn_name) + 1;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	if (!elf_utils_shift_contents(e, shdr.sh_offset + shdr.sh_size, namelen))
		goto failure;
	ASSERT(ptr = realloc(shstrdata->d_buf, shstrdata->d_size + namelen));
	index = shstrdata->d_size;
	strcpy(ptr + index, scn_name);
	shstrdata->d_buf = ptr;
	shstrdata->d_size += namelen;
	shdr.sh_size += namelen;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	ELF_ASSERT(scn = elf_newscn(e));
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_name = index;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	return scn;
failure:
	return NULL;
}
int velf_modinfo_write(Elf* dest, const velf_t* ve, const sce_section_sizes_t* section_sizes, void* modinfo) {
	/* Corresponds to the order in sce_section_sizes_t */

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(dest, &ehdr));

	int segndx;
	for (segndx = 0; segndx < ve->num_segments; segndx++) {
		if (ehdr.e_entry >= ve->segments[segndx].vaddr && ehdr.e_entry < ve->segments[segndx].vaddr + ve->segments[segndx].memsz)
			break;
	}
	ASSERT(segndx < ve->num_segments);

	GElf_Phdr phdr;
	ELF_ASSERT(gelf_getphdr(dest, segndx, &phdr));

	Elf32_Addr segment_base    = ve->segments[segndx].vaddr;
	Elf32_Word start_segoffset = (ve->segments[segndx].memsz + 0xF) & ~0xF; // align to 16 bytes, same with `velf_modinfo_encode`
	Elf32_Addr start_vaddr     = segment_base + start_segoffset;
	Elf32_Word start_foffset   = phdr.p_offset + start_segoffset;

	int total_size = velf_modinfo_sum_size(section_sizes) + (start_segoffset - ve->segments[segndx].memsz); // add the padding size
	if (!elf_utils_shift_contents(dest, start_foffset, total_size))
		DIE("Unable to relocate ELF sections");

	/* Extend in our copy of phdrs so that velf_vaddr_to_segndx can match it */
	ve->segments[segndx].memsz += total_size;
	phdr.p_filesz += total_size;
	phdr.p_memsz += total_size;
	ELF_ASSERT(gelf_update_phdr(dest, segndx, &phdr));

	ELF_ASSERT(gelf_getehdr(dest, &ehdr));
	ehdr.e_entry = ((segndx & 0x3) << 30) | start_segoffset;
	ELF_ASSERT(gelf_update_ehdr(dest, &ehdr));

	Elf32_Word* sizes = (Elf32_Word*)section_sizes;
	size_t      count = sizeof(*section_sizes) / sizeof(*sizes);
	for (int cur_pos = 0, i = 0; i < count; i++) {
		int scn_size = sizes[i];
		if (scn_size == 0)
			continue;

		Elf_Scn*  scn = elf_utils_new_scn_with_name(dest, section_names[i]);
		GElf_Shdr shdr;
		ELF_ASSERT(gelf_getshdr(scn, &shdr));
		shdr.sh_type      = SHT_PROGBITS;
		shdr.sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
		shdr.sh_addr      = start_vaddr + cur_pos;
		shdr.sh_offset    = start_foffset + cur_pos;
		shdr.sh_size      = scn_size;
		shdr.sh_addralign = 4;
		ELF_ASSERT(gelf_update_shdr(scn, &shdr));

		Elf_Data* data;
		ELF_ASSERT(data = elf_newdata(scn));
		data->d_buf     = modinfo + cur_pos;
		data->d_type    = ELF_T_BYTE;
		data->d_version = EV_CURRENT;
		data->d_size    = scn_size;
		data->d_off     = 0;
		data->d_align   = 1;

		cur_pos += scn_size;
	}

	return 1;
failure:
	return 0;
}
static int sce_rel_new(velf_reloc* rel, int symseg, int code, int datseg, int offset, int addend) {
	/*
	if (addend > 1 << 11)
		return 0;
	rel->r_short_entry.r_short     = 1;
	rel->r_short_entry.r_symseg    = symseg;
	rel->r_short_entry.r_code      = code;
	rel->r_short_entry.r_datseg    = datseg;
	rel->r_short_entry.r_offset_lo = offset & 0xFFF;
	rel->r_short_entry.r_offset_hi = offset >> 20;
	rel->r_short_entry.r_addend    = addend;
	*/
	rel->r_long_entry.r_short  = 0;
	rel->r_long_entry.r_symseg = symseg;
	rel->r_long_entry.r_code   = code;
	rel->r_long_entry.r_datseg = datseg;
	rel->r_long_entry.r_code2  = 0;
	rel->r_long_entry.r_dist2  = 0;
	rel->r_long_entry.r_offset = offset;
	rel->r_long_entry.r_addend = addend;
	return 1;
}
static int encode_sce_rel(velf_reloc* rel) {
	if (rel->r_short_entry.r_short) {
		rel->r_raw_entry.r_word1 = htole32((rel->r_short_entry.r_short) | (rel->r_short_entry.r_symseg << 4) | (rel->r_short_entry.r_code << 8) |
		                                   (rel->r_short_entry.r_datseg << 16) | (rel->r_short_entry.r_offset_lo << 20));
		rel->r_raw_entry.r_word2 = htole32((rel->r_short_entry.r_offset_hi) | (rel->r_short_entry.r_addend << 20));

		return 8;
	} else {
		rel->r_raw_entry.r_word1 = htole32((rel->r_long_entry.r_short) | (rel->r_long_entry.r_symseg << 4) | (rel->r_long_entry.r_code << 8) |
		                                   (rel->r_long_entry.r_datseg << 16) | (rel->r_long_entry.r_code2 << 20) | (rel->r_long_entry.r_dist2 << 28));
		rel->r_raw_entry.r_word2 = htole32(rel->r_long_entry.r_addend);
		rel->r_raw_entry.r_word3 = htole32(rel->r_long_entry.r_offset);
		return 12;
	}
}

/* We have to check all relocs. If any of the point to a space in ELF that is not contained in any segment,
 * we should discard this reloc. This should be done before we extend the code segment with modinfo, because otherwise
 * the invalid addresses may become valid */
int velf_reloc_table_strip(const velf_t* ve, velf_rela_table_t* rtable) {
	for (velf_rela_table_t* curtable = rtable; curtable; curtable = curtable->next) {
		int i = 0;
		for (velf_rela_t* vrela = curtable->relas; i < curtable->num_relas; i++, vrela++) {
			if (vrela->type == R_ARM_NONE || (vrela->symbol && vrela->symbol->shndx == 0)) {
				vrela->type = R_ARM_NONE;
				continue;
			}
			/* We skip relocations that are not real relocations 
			 * In all current tested output, we have that the unrelocated value is correct. 
			 * However, there is nothing that says this has to be the case. SCE RELS 
			 * does not support ABS value relocations anymore, so there's not much 
			 * we can do. */
			// TODO: Consider a better solution for this.
			if (vrela->symbol && (vrela->symbol->shndx == SHN_ABS || vrela->symbol->shndx == SHN_COMMON)) {
				vrela->type = R_ARM_NONE;
				continue;
			}
			int datseg = velf_vaddr_to_segndx(ve, vrela->offset);
			/* We can get -1 here for some debugging-related relocations.
			 * These are done against debug sections that aren't mapped to any segment.
			 * Just ignore these */
			if (datseg == -1)
				vrela->type = R_ARM_NONE;
		}
	}
	return 1;
}
Elf_Scn* elf_utils_new_scn_with_data(Elf* e, const char* scn_name, void* buf, int len) {
	Elf_Scn* scn = elf_utils_new_scn_with_name(e, scn_name);
	if (scn == NULL)
		goto failure;

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	int offset = ehdr.e_shoff;
	if (!elf_utils_shift_contents(e, offset, len + 0x10))
		goto failure;

	GElf_Shdr shdr;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_offset    = (offset + 0x10) & ~0xF;
	shdr.sh_size      = len;
	shdr.sh_addralign = 1;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	Elf_Data* data;
	ELF_ASSERT(data = elf_newdata(scn));
	data->d_buf     = buf;
	data->d_type    = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	data->d_size    = len;
	data->d_off     = 0;
	data->d_align   = 1;

	return scn;
failure:
	return NULL;
}

int velf_rela_table_write(Elf* dest, const velf_t* ve, const velf_rela_table_t* rtable) {
	int                      total_relas = 0;
	const velf_rela_table_t* curtable;
	const velf_rela_t*       vrela;
	void *                   encoded_relas = NULL, *curpos;
	velf_reloc               rel;
	int                      relsz;
	int                      i;
	Elf32_Addr               symvaddr;
	Elf32_Word               symseg, symoff;
	Elf32_Word               datseg, datoff;
	int (*sce_rel_func)(velf_reloc*, int, int, int, int, int);

	for (curtable = rtable; curtable; curtable = curtable->next)
		total_relas += curtable->num_relas;

	ASSERT(encoded_relas = calloc(total_relas, 12));

	// sce_rel_func = sce_rel_short;
	sce_rel_func = sce_rel_new;

encode_relas:
	curpos = encoded_relas;

	for (curtable = rtable; curtable; curtable = curtable->next) {
		for (i = 0, vrela = curtable->relas; i < curtable->num_relas; i++, vrela++) {
			if (vrela->type == R_ARM_NONE)
				continue;
			datseg = velf_vaddr_to_segndx(ve, vrela->offset);
			datoff = velf_vaddr_to_segoffset(ve, vrela->offset, datseg);
			if (vrela->symbol) {
				symvaddr = vrela->symbol->value + vrela->addend;
			} else {
				symvaddr = vrela->addend;
			}
			symseg = velf_vaddr_to_segndx(ve, vrela->symbol ? vrela->symbol->value : vrela->addend);
			if (symseg == -1)
				continue;
			symoff = velf_vaddr_to_segoffset(ve, symvaddr, symseg);
			if (!sce_rel_func(&rel, symseg, vrela->type, datseg, datoff, symoff)) {
				sce_rel_func = sce_rel_new;
				goto encode_relas;
			}
			relsz = encode_sce_rel(&rel);
			memcpy(curpos, &rel, relsz);
			curpos += relsz;
		}
	}

	Elf_Scn* scn = elf_utils_new_scn_with_data(dest, ".sce.rel", encoded_relas, curpos - encoded_relas);
	if (scn == NULL)
		goto failure;
	encoded_relas = NULL;

	GElf_Shdr shdr;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_type      = SHT_SCE_RELA;
	shdr.sh_flags     = 0;
	shdr.sh_addralign = 4;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));
	size_t segment_count = 0;
	ELF_ASSERT((elf_getphdrnum(dest, &segment_count), segment_count > 0));
	GElf_Phdr phdrs[8]; // usually 3~4
	ASSERT(segment_count < sizeof(phdrs) / sizeof(*phdrs));
	for (i = 0; i < segment_count; i++) {
		ELF_ASSERT(gelf_getphdr(dest, i, phdrs + i));
	}
	ELF_ASSERT(gelf_newphdr(dest, segment_count + 1));
	ELF_ASSERT(gelf_getphdr(dest, segment_count, phdrs + segment_count));
	phdrs[segment_count].p_type   = PT_SCE_RELA;
	phdrs[segment_count].p_offset = shdr.sh_offset;
	phdrs[segment_count].p_filesz = shdr.sh_size;
	phdrs[segment_count].p_align  = 16;
	for (i = 0; i < segment_count + 1; i++) {
		ELF_ASSERT(gelf_update_phdr(dest, i, phdrs + i));
	}

	return 1;

failure:
	free(encoded_relas);
	return 0;
}

int velf_stubs_rewrite(Elf* dest, const velf_t* ve) {
	Elf_Scn*  scn;
	GElf_Shdr shdr;
	Elf_Data* data;
	size_t    shstrndx;
	void*     shstrtab;
	uint32_t* stubdata;
	int       j;
	int*      cur_ndx;
	char *    sh_name, *stub_name;

	ELF_ASSERT(elf_getshdrstrndx(dest, &shstrndx) == 0);
	ELF_ASSERT(scn = elf_getscn(dest, shstrndx));
	ELF_ASSERT(data = elf_getdata(scn, NULL));
	shstrtab = data->d_buf;

	for (j = 0; j < ve->fstubs_va.count; j++) {
		cur_ndx = VARRAY_ELEMENT(&ve->fstubs_va, j);
		ELF_ASSERT(scn = elf_getscn(dest, *cur_ndx));
		ELF_ASSERT(gelf_getshdr(scn, &shdr));

		sh_name = shstrtab + shdr.sh_name;
		if (strstr(sh_name, VELF_SEC_FSTUB ".") != sh_name) {
			DIE("Malformed " VELF_SEC_FSTUB " section. out-of-date SDK lib ?");
		}
		stub_name = strrchr(sh_name, '.');
		snprintf(sh_name, strlen(sh_name) + 1, ".text.fstubs%s", stub_name);

		data = NULL;
		while ((data = elf_getdata(scn, data)) != NULL) {
			for (stubdata = (uint32_t*)data->d_buf; (void*)stubdata < data->d_buf + data->d_size - 11; stubdata += 4) {
				stubdata[0] = htole32(sce_elf_stub_func[0]);
				stubdata[1] = htole32(sce_elf_stub_func[1]);
				stubdata[2] = htole32(sce_elf_stub_func[2]);
				stubdata[3] = 0;
			}
		}
	}

	/* If the section index is zero, it means that it's nonexistent */
	if (ve->vstubs_va.count == 0) {
		return 1;
	}

	for (j = 0; j < ve->vstubs_va.count; j++) {
		cur_ndx = VARRAY_ELEMENT(&ve->vstubs_va, j);
		ELF_ASSERT(scn = elf_getscn(dest, *cur_ndx));
		ELF_ASSERT(gelf_getshdr(scn, &shdr));

		sh_name = shstrtab + shdr.sh_name;
		if (strstr(sh_name, VELF_SEC_VSTUB ".") != sh_name) {
			DIE("malformed " VELF_SEC_VSTUB " section. out-of-date sdk lib ?");
		}
		stub_name = strrchr(sh_name, '.');
		snprintf(sh_name, strlen(sh_name) + 1, ".data.vstubs%s", stub_name);

		data = NULL;
		while ((data = elf_getdata(scn, data)) != NULL) {
			for (stubdata = (uint32_t*)data->d_buf; (void*)stubdata < data->d_buf + data->d_size - 11; stubdata += 4) {
				memset(stubdata, 0, 16);
			}
		}
	}

	return 1;
failure:
	return 0;
}

int velf_type(FILE* destfile, uint16_t type) {
	Elf32_Ehdr ehdr = {.e_type = htole16(type)};
	ASSERT(fseek(destfile, offsetof(Elf32_Ehdr, e_type), SEEK_SET) >= 0);
	ASSERT(fwrite(&ehdr.e_type, sizeof(ehdr.e_type), 1, destfile) >= 0);

	return 1;
failure:
	return 0;
}

int elf_utils_copy(Elf* dest, Elf* source) {
	GElf_Ehdr ehdr;
	Elf_Scn * dst_scn, *src_scn;
	GElf_Shdr shdr;
	Elf_Data *dst_data, *src_data;
	size_t    segment_count, segndx, new_segndx;
	GElf_Phdr phdr;

	ELF_ASSERT(elf_flagelf(dest, ELF_C_SET, ELF_F_LAYOUT));

	ELF_ASSERT(gelf_getehdr(source, &ehdr));
	ELF_ASSERT(gelf_newehdr(dest, gelf_getclass(source)));
	ELF_ASSERT(gelf_update_ehdr(dest, &ehdr));

	src_scn = NULL;
	while ((src_scn = elf_nextscn(source, src_scn)) != NULL) {
		ELF_ASSERT(gelf_getshdr(src_scn, &shdr));
		ELF_ASSERT(dst_scn = elf_newscn(dest));
		ELF_ASSERT(gelf_update_shdr(dst_scn, &shdr));

		src_data = NULL;
		while ((src_data = elf_getdata(src_scn, src_data)) != NULL) {
			ELF_ASSERT(dst_data = elf_newdata(dst_scn));
			memcpy(dst_data, src_data, sizeof(Elf_Data));
		}
	}

	ELF_ASSERT(elf_getphdrnum(source, &segment_count) == 0);

	// only count PT_LOAD segments
	new_segndx = 0;
	for (segndx = 0; segndx < segment_count; segndx++) {
		ELF_ASSERT(gelf_getphdr(source, segndx, &phdr));
		if (phdr.p_type == PT_LOAD) {
			new_segndx++;
		}
	}
	ASSERT(new_segndx > 0);

	// copy PT_LOAD segments
	ELF_ASSERT(gelf_newphdr(dest, new_segndx));
	new_segndx = 0;
	for (segndx = 0; segndx < segment_count; segndx++) {
		ELF_ASSERT(gelf_getphdr(source, segndx, &phdr));
		if (phdr.p_type == PT_LOAD) {
			ELF_ASSERT(gelf_update_phdr(dest, new_segndx, &phdr));
			new_segndx++;
		}
	}

	return 1;
failure:
	return 0;
}

int elf_utils_duplicate_scn_contents(Elf* e, int scndx) {
	Elf_Scn*  scn;
	Elf_Data* data;
	void*     new_data;

	ELF_ASSERT(scn = elf_getscn(e, scndx));

	data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		ASSERT(new_data = malloc(data->d_size));
		memcpy(new_data, data->d_buf, data->d_size);
		data->d_buf = new_data;
	}

	return 1;
failure:
	return 0;
}

void elf_utils_free_scn_contents(Elf* e, int scndx) {
	Elf_Scn*  scn;
	Elf_Data* data;

	ELF_ASSERT(scn = elf_getscn(e, scndx));

	data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		free(data->d_buf);
		data->d_buf = NULL;
	}

failure:
	return;
}

int elf_utils_duplicate_shstrtab(Elf* e) {
	size_t shstrndx;

	ELF_ASSERT(elf_getshdrstrndx(e, &shstrndx) == 0);

	return elf_utils_duplicate_scn_contents(e, shstrndx);
failure:
	return 0;
}

void print_stubs(velf_stub_t* stubs, int num_stubs) {
	int i;

	for (i = 0; i < num_stubs; i++) {
		LOG("  0x%06x (%s):\n", stubs[i].addr, stubs[i].symbol ? stubs[i].symbol->name : "unreferenced stub");
		LOG("    Flags  : %u\n", stubs[i].library ? stubs[i].library->flags : 0);
		LOG("    Library: %u (%s)\n", stubs[i].library_nid, stubs[i].library ? stubs[i].library->name : "not found");
		LOG("    nid    : %u (%s)\n", stubs[i].target_nid, stubs[i].target ? stubs[i].target->name : "not found");
	}
}

const char* elf_decode_r_type(int r_type) {
	switch (r_type) {
	case R_ARM_NONE:
		return "R_ARM_NONE";
	case R_ARM_V4BX:
		return "R_ARM_V4BX";
	case R_ARM_ABS32:
		return "R_ARM_ABS32";
	case R_ARM_REL32:
		return "R_ARM_REL32";
	case R_ARM_THM_CALL:
		return "R_ARM_THM_CALL";
	case R_ARM_CALL:
		return "R_ARM_CALL";
	case R_ARM_JUMP24:
		return "R_ARM_JUMP24";
	case R_ARM_TARGET1:
		return "R_ARM_TARGET1";
	case R_ARM_TARGET2:
		return "R_ARM_TARGET2";
	case R_ARM_PREL31:
		return "R_ARM_PREL31";
	case R_ARM_MOVW_ABS_NC:
		return "R_ARM_MOVW_ABS_NC";
	case R_ARM_MOVT_ABS:
		return "R_ARM_MOVT_ABS";
	case R_ARM_THM_MOVW_ABS_NC:
		return "R_ARM_THM_MOVW_ABS_NC";
	case R_ARM_THM_MOVT_ABS:
		return "R_ARM_THM_MOVT_ABS";
	}

	return "<<INVALID RELOCATION>>";
}

void print_rtable(velf_rela_table_t* rtable) {
	velf_rela_t* rela;
	int          num_relas;

	for (num_relas = rtable->num_relas, rela = rtable->relas; num_relas; num_relas--, rela++) {
		if (rela->symbol) {
			LOG("    offset %06x: type %s, %s%+d\n", rela->offset, elf_decode_r_type(rela->type), rela->symbol->name, rela->addend);
		} else if (rela->offset) {
			LOG("    offset %06x: type %s, absolute %06x\n", rela->offset, elf_decode_r_type(rela->type), (uint32_t)rela->addend);
		}
	}
}

void list_rels(velf_t* ve) {
	velf_rela_table_t* rtable;

	for (rtable = ve->rela_tables; rtable; rtable = rtable->next) {
		LOG("  Relocations for section#%d\n", rtable->target_ndx);
		print_rtable(rtable);
	}
}

void list_segments(velf_t* ve) {
	int i;

	for (i = 0; i < ve->num_segments; i++) {
		LOG("  Segment %d: vaddr %06x, size 0x%x\n", i, ve->segments[i].vaddr, ve->segments[i].memsz);
		if (ve->segments[i].memsz) {
			LOG("    Host address region: %p - %p\n", ve->segments[i].vaddr_top, ve->segments[i].vaddr_bottom);
			LOG("    4 bytes into segment (%p): %x\n", ve->segments[i].vaddr_top + 4, velf_host_to_vaddr(ve, ve->segments[i].vaddr_top + 4));
			LOG("    addr of 8 bytes into segment (%x): %p\n", ve->segments[i].vaddr + 8, velf_vaddr_to_host(ve, ve->segments[i].vaddr + 8));
			LOG("    12 bytes into segment offset (%p): %d\n", ve->segments[i].vaddr_top + 12, velf_host_to_segoffset(ve, ve->segments[i].vaddr_top + 12, i));
			LOG("    addr of 16 bytes into segment (%d): %p\n", 16, velf_segoffset_to_host(ve, i, 16));
		}
	}
}

#endif
