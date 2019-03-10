#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* This file can gets included multiple times to generate host-visible + target-visible versions of each struct */
#if defined(SCE_ELF_DEFS_HOST) || defined(SCE_ELF_DEFS_TARGET)
#if defined(SCE_ELF_DEFS_HOST)
#define SCE_TYPE(type) type##_t
#define SCE_PTR(type) type
#elif defined(SCE_ELF_DEFS_TARGET)
#define SCE_TYPE(type) type##_raw
#define SCE_PTR(type) uint32_t
#endif

struct SCE_TYPE(sce_module_exports);
struct SCE_TYPE(sce_module_imports);

typedef struct SCE_TYPE(sce_module_info) {
	uint16_t attributes;
	uint16_t version;                                 /* Set to 0x0101 */
	char     name[27];                                /* Name of the library */
	uint8_t  type;                                    /* 0x0 for executable, 0x6 for PRX */
	SCE_PTR(const void*) gp_value;                    /* */
	SCE_PTR(struct sce_module_exports_t*) export_top; /* Offset to start of export table */
	SCE_PTR(struct sce_module_exports_t*) export_end; /* Offset to end of export table */
	SCE_PTR(struct sce_module_imports_t*) import_top; /* Offset to start of import table */
	SCE_PTR(struct sce_module_imports_t*) import_end; /* Offset to end of import table */
	uint32_t library_nid;                             /* NID of this library */
	uint32_t field_38;
	uint32_t field_3C;
	uint32_t field_40;
	SCE_PTR(const void*) module_start; /* Offset to function to run when library is started, 0 to disable */
	SCE_PTR(const void*) module_stop;  /* Offset to function to run when library is exiting, 0 to disable */
	SCE_PTR(const void*) exidx_top;    /* Offset to start of ARM EXIDX (optional) */
	SCE_PTR(const void*) exidx_end;    /* Offset to end of ARM EXIDX (optional) */
	SCE_PTR(const void*) extab_top;    /* Offset to start of ARM EXTAB (optional) */
	SCE_PTR(const void*) extab_end;    /* Offset to end of ARM EXTAB (optional */

	// i decided to include process param into module_info (xyz)
	uint32_t process_param_size;
	uint32_t process_param_magic;
	uint32_t process_param_unk[11];
} SCE_TYPE(sce_module_info);

typedef struct SCE_TYPE(sce_module_exports) {
	uint16_t size;           /* Size of this struct, set to 0x20 */
	uint16_t version;        /* 0x1 for normal export, 0x0 for main module export */
	uint16_t flags;          /* 0x1 for normal export, 0x8000 for main module export */
	uint16_t num_syms_funcs; /* Number of function exports */
	uint32_t num_syms_vars;  /* Number of variable exports */
	uint32_t num_syms_unk;
	uint32_t module_nid;               /* NID of this module */
	SCE_PTR(const char*) module_name;  /* Pointer to name of this module */
	SCE_PTR(uint32_t*) nid_table;      /* Pointer to array of 32-bit NIDs to export */
	SCE_PTR(const void**) entry_table; /* Pointer to array of data pointers for each NID */
} SCE_TYPE(sce_module_exports);

typedef struct SCE_TYPE(sce_module_imports) {
	uint16_t size;           /* Size of this struct, set to 0x34 */
	uint16_t version;        /* Set to 0x1 */
	uint16_t flags;          /* Set to 0x0 */
	uint16_t num_syms_funcs; /* Number of function imports */
	uint16_t num_syms_vars;  /* Number of variable imports */
	uint16_t num_syms_unk;
	uint32_t reserved1;
	uint32_t module_nid;              /* NID of module to import */
	SCE_PTR(const char*) module_name; /* Pointer to name of imported module, for debugging */
	uint32_t reserved2;
	SCE_PTR(uint32_t*) func_nid_table;      /* Pointer to array of function NIDs to import */
	SCE_PTR(const void**) func_entry_table; /* Pointer to array of stub functions to fill */
	SCE_PTR(uint32_t*) var_nid_table;       /* Pointer to array of variable NIDs to import */
	SCE_PTR(const void**) var_entry_table;  /* Pointer to array of data pointers to write to */
	SCE_PTR(uint32_t*) unk_nid_table;
	SCE_PTR(const void**) unk_entry_table;
} SCE_TYPE(sce_module_imports);

#undef SCE_TYPE
#undef SCE_PTR
#endif

#ifndef SCE_ELF_H
#define SCE_ELF_H

// https://wiki.osdev.org/ELF_Tutorial
/* SCE-specific definitions for e_phnum */
#define PH_SCE_MAX_EXEC 5
#define PH_SCE_MAX_RELEXEC 8
#define PH_SCE_MAX_PT_LOAD 3
#define PH_SCE_MAX_SCE_RELOC 3

/* SCE-specific definitions for e_type: */
#define ET_SCE_EXEC 0xFE00       /* SCE Executable file */
#define ET_SCE_RELEXEC 0xFE04    /* SCE Relocatable file */
#define ET_SCE_STUBLIB 0xFE0C    /* SCE SDK Stubs */
#define ET_SCE_DYNAMIC 0xFE18    /* Unused */
#define ET_SCE_PSPRELEXEC 0xFFA0 /* Unused (PSP ELF only) */
#define ET_SCE_PPURELEXEC 0xFFA4 /* Unused (SPU ELF only) */
#define ET_SCE_UNK 0xFFA5        /* Unknown */

/* SCE-specific definitions for sh_type: */
#define SHT_SCE_RELA 0x60000000    /* SCE Relocations */
#define SHT_SCENID 0x61000001      /* Unused (PSP ELF only) */
#define SHT_SCE_PSPRELA 0x700000A0 /* Unused (PSP ELF only) */
#define SHT_SCE_ARMRELA 0x700000A4 /* Unused (PSP ELF only) */

/* SCE-specific definitions for p_type: */
#define PT_SCE_RELA 0x60000000    /* SCE Relocations */
#define PT_SCE_COMMENT 0x6FFFFF00 /* Unused */
#define PT_SCE_VERSION 0x6FFFFF01 /* Unused */
#define PT_SCE_UNK 0x70000001     /* Unknown */
#define PT_SCE_PSPRELA 0x700000A0 /* Unused (PSP ELF only) */
#define PT_SCE_PPURELA 0x700000A4 /* Unused (SPU ELF only) */

#define NID_MODULE_STOP 0x79F8E492
#define NID_MODULE_EXIT 0x913482A9
#define NID_MODULE_START 0x935CD196
#define NID_MODULE_INFO 0x6C2224BA
#define NID_PROCESS_PARAM 0x70FBA1E7

#ifndef R_ARM_NONE
#define R_ARM_NONE 0
#endif
#ifndef R_ARM_ABS32
#define R_ARM_ABS32 2
#endif

/*
Segment start = Base address of segment indexed at `r_datseg`
Symbol start = Base address of segment indexed at `r_symseg`
P = segment start + `r_offset`
S = symbol start
A = `r_addend`

SHT_PROGBITS Operation :

Code | Name | Operation
---- | ---- | ---------
0    | R_ARM_NONE
2    | R_ARM_ABS32 | S+A
3    | R_ARM_REL32 | S+A−P
10   | R_ARM_THM_CALL | S+A−P
28   | R_ARM_CALL | S+A−P
29   | R_ARM_JUMP24 | S+A−P
38   | R_ARM_TARGET1 (same as R_ARM_ABS32) | S+A
40   | R_ARM_V4BX (same as R_ARM_NONE)
41   | R_ARM_TARGET2 (same as R_ARM_REL32) | S+A−P
42   | R_ARM_PREL31 | S+A−P
43   | R_ARM_MOVW_ABS_NC | S+A
44   | R_ARM_MOVT_ABS | S+A
47   | R_ARM_THM_MOVW_ABS_NC | S+A
48   | R_ARM_THM_MOVT_ABS | S+A
*/

typedef union {
	uint32_t r_short : 4;
	struct {
		uint32_t r_short : 4;
		uint32_t r_symseg : 4;
		uint32_t r_code : 8;
		uint32_t r_datseg : 4;
		uint32_t r_offset_lo : 12;
		uint32_t r_offset_hi : 20;
		uint32_t r_addend : 12;
	} r_short_entry;
	struct {
		uint32_t r_short : 4;
		uint32_t r_symseg : 4;
		uint32_t r_code : 8;
		uint32_t r_datseg : 4;
		uint32_t r_code2 : 8;
		uint32_t r_dist2 : 4;
		uint32_t r_addend;
		uint32_t r_offset;
	} r_long_entry;
	struct {
		uint32_t r_word1;
		uint32_t r_word2;
		uint32_t r_word3;
	} r_raw_entry;
} SCE_Rel;

typedef struct {
	const char* name;
	uint32_t    nid;
} vita_export_symbol;

typedef struct {
	const char*          name;
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
	const char*           start;
	const char*           stop;
	const char*           exit;
	size_t                module_n;
	vita_library_export** modules;
} vita_export_t;

#define SCE_ELF_DEFS_HOST
#include "velf.h"
#undef SCE_ELF_DEFS_HOST

#define SCE_ELF_DEFS_TARGET
#include "velf.h"
#undef SCE_ELF_DEFS_TARGET

/* This struct must only contain uint32_t, because we use it as an array */
typedef struct {
	uint32_t sceModuleInfo_rodata; /* The sce_module_info structure */
	uint32_t sceLib_ent;           /* All sce_module_exports structures */
	uint32_t sceExport_rodata;     /* The tables referenced by sce_module_exports */
	uint32_t sceLib_stubs;         /* All sce_module_imports structures */
	uint32_t sceImport_rodata;     /* Misc data referenced by sce_module_imports */
	uint32_t sceFNID_rodata;       /* The imported function NID arrays */
	uint32_t sceFStub_rodata;      /* The imported function pointer arrays */
	uint32_t sceVNID_rodata;       /* The imported function NID arrays */
	uint32_t sceVStub_rodata;      /* The imported function NID arrays */
} sce_section_sizes_t;

#define R_ARM_NONE 0
#define R_ARM_ABS32 2
#define R_ARM_REL32 3
#define R_ARM_THM_CALL 10
#define R_ARM_CALL 28
#define R_ARM_JUMP24 29
#define R_ARM_THM_JUMP24 30
#define R_ARM_TARGET1 38
#define R_ARM_SBREL31 39
#define R_ARM_V4BX 40
#define R_ARM_TARGET2 41
#define R_ARM_PREL31 42
#define R_ARM_MOVW_ABS_NC 43
#define R_ARM_MOVT_ABS 44
#define R_ARM_MOVW_PREL_NC 45
#define R_ARM_MOVT_PREL 46
#define R_ARM_THM_MOVW_ABS_NC 47
#define R_ARM_THM_MOVT_ABS 48
#define R_ARM_THM_PC11 102

#ifndef SHT_ARM_EXIDX
#define SHT_ARM_EXIDX 0x70000001
#endif

/* These fields must always come at the beginning of the NID-bearing structs */
typedef struct {
	char*    name;
	uint32_t NID;
} vita_imports_common_fields;

typedef struct {
	char*    name;
	uint32_t NID;
} vita_imports_stub_t;

typedef struct {
	char*                 name;
	uint32_t              NID;
	bool                  is_kernel;
	vita_imports_stub_t** functions;
	vita_imports_stub_t** variables;
	int                   n_functions;
	int                   n_variables;
	uint32_t              flags;
} vita_imports_module_t;

typedef struct {
	char*                   name;
	uint32_t                NID;
	vita_imports_module_t** modules;
	int                     n_modules;
} vita_imports_lib_t;

typedef struct {
	vita_imports_lib_t** libs;
	int                  n_libs;
} vita_imports_t;

/* Convenience representation of a symtab entry */
typedef struct vita_elf_symbol_t {
	const char* name;
	uint32_t    value;
	uint8_t     type;
	uint8_t     binding;
	int         shndx;
} vita_elf_symbol_t;

typedef struct vita_elf_rela_t {
	uint8_t            type;
	vita_elf_symbol_t* symbol;
	uint32_t           offset;
	int32_t            addend;
} vita_elf_rela_t;

typedef struct vita_elf_rela_table_t {
	vita_elf_rela_t* relas;
	int              num_relas;

	int target_ndx;

	struct vita_elf_rela_table_t* next;
} vita_elf_rela_table_t;

typedef struct {
	uint32_t addr;
	uint32_t module_nid;
	uint32_t target_nid;

	vita_elf_symbol_t* symbol;

	vita_imports_module_t* module;
	vita_imports_stub_t*   target;
} vita_elf_stub_t;

typedef struct {
	uint32_t type;  /* Segment type */
	uint32_t vaddr; /* Top of segment space on TARGET */
	uint32_t memsz; /* Size of segment space */

	/* vaddr_top/vaddr_bottom point to a reserved, unallocated memory space that
	 * represents the segment space in the HOST.  This space can be used as
	 * pointer targets for translated data structures. */
	const void* vaddr_top;
	const void* vaddr_bottom;
} vita_elf_segment_info_t;

#endif
