/* This file gets included multiple times to generate the host-visible and target-visible versions of each struct */

#if defined(SCE_ELF_DEFS_HOST)
# define SCE_TYPE(type) type ## _t
# define SCE_PTR(type) type
#elif defined(SCE_ELF_DEFS_TARGET)
# define SCE_TYPE(type) type ## _raw
# define SCE_PTR(type) uint32_t
#endif

#if defined(SCE_ELF_DEFS_HOST) || defined(SCE_ELF_DEFS_TARGET)
#include <stdint.h>
struct SCE_TYPE(sce_module_exports);
struct SCE_TYPE(sce_module_imports);

typedef struct SCE_TYPE(sce_module_info) {
	uint16_t attributes;
	uint16_t version;                                 /* Set to 0x0101 */
	char name[27];                                    /* Name of the library */
	uint8_t type;                                     /* 0x0 for executable, 0x6 for PRX */
	SCE_PTR(const void *)gp_value;                    /* */
	SCE_PTR(struct sce_module_exports_t *)export_top; /* Offset to start of export table */
	SCE_PTR(struct sce_module_exports_t *)export_end; /* Offset to end of export table */
	SCE_PTR(struct sce_module_imports_t *)import_top; /* Offset to start of import table */
	SCE_PTR(struct sce_module_imports_t *)import_end; /* Offset to end of import table */
	uint32_t library_nid;                             /* NID of this library */
	uint32_t field_38;
	uint32_t field_3C;
	uint32_t field_40;
	SCE_PTR(const void *)module_start;                /* Offset to function to run when library is started, 0 to disable */
	SCE_PTR(const void *)module_stop;                 /* Offset to function to run when library is exiting, 0 to disable */
	SCE_PTR(const void *)exidx_top;                   /* Offset to start of ARM EXIDX (optional) */
	SCE_PTR(const void *)exidx_end;                   /* Offset to end of ARM EXIDX (optional) */
	SCE_PTR(const void *)extab_top;                   /* Offset to start of ARM EXTAB (optional) */
	SCE_PTR(const void *)extab_end;                   /* Offset to end of ARM EXTAB (optional */

	// i decided to include process param into module_info (xyz)
	uint32_t process_param_size;
	uint32_t process_param_magic;
	uint32_t process_param_unk[11];
} SCE_TYPE(sce_module_info);

typedef struct SCE_TYPE(sce_module_exports) {
	uint16_t size;        /* Size of this struct, set to 0x20 */
	uint16_t version;      /* 0x1 for normal export, 0x0 for main module export */
	uint16_t flags;        /* 0x1 for normal export, 0x8000 for main module export */
	uint16_t num_syms_funcs;    /* Number of function exports */
	uint32_t num_syms_vars;      /* Number of variable exports */
	uint32_t num_syms_unk;
	uint32_t module_nid;      /* NID of this module */
	SCE_PTR(const char *)module_name;  /* Pointer to name of this module */
	SCE_PTR(uint32_t *)nid_table;    /* Pointer to array of 32-bit NIDs to export */
	SCE_PTR(const void **)entry_table;  /* Pointer to array of data pointers for each NID */
} SCE_TYPE(sce_module_exports);

typedef struct SCE_TYPE(sce_module_imports) {
	uint16_t size;        /* Size of this struct, set to 0x34 */
	uint16_t version;      /* Set to 0x1 */
	uint16_t flags;        /* Set to 0x0 */
	uint16_t num_syms_funcs;    /* Number of function imports */
	uint16_t num_syms_vars;      /* Number of variable imports */
	uint16_t num_syms_unk;
	uint32_t reserved1;
	uint32_t module_nid;      /* NID of module to import */
	SCE_PTR(const char *)module_name;  /* Pointer to name of imported module, for debugging */
	uint32_t reserved2;
	SCE_PTR(uint32_t *)func_nid_table;  /* Pointer to array of function NIDs to import */
	SCE_PTR(const void **)func_entry_table;/* Pointer to array of stub functions to fill */
	SCE_PTR(uint32_t *)var_nid_table;  /* Pointer to array of variable NIDs to import */
	SCE_PTR(const void **)var_entry_table;  /* Pointer to array of data pointers to write to */
	SCE_PTR(uint32_t *)unk_nid_table;
	SCE_PTR(const void **)unk_entry_table;
} SCE_TYPE(sce_module_imports);

#undef SCE_TYPE
#undef SCE_PTR
#endif

#ifndef SCE_ELF_H
#define SCE_ELF_H

/* SCE-specific definitions for e_type: */
#define ET_SCE_EXEC		0xFE00		/* SCE Executable file */
#define ET_SCE_RELEXEC		0xFE04		/* SCE Relocatable file */
#define ET_SCE_STUBLIB		0xFE0C		/* SCE SDK Stubs */
#define ET_SCE_DYNAMIC		0xFE18		/* Unused */
#define ET_SCE_PSPRELEXEC	0xFFA0		/* Unused (PSP ELF only) */
#define ET_SCE_PPURELEXEC	0xFFA4		/* Unused (SPU ELF only) */
#define ET_SCE_UNK		0xFFA5		/* Unknown */

/* SCE-specific definitions for sh_type: */
#define SHT_SCE_RELA		0x60000000	/* SCE Relocations */
#define SHT_SCENID		0x61000001	/* Unused (PSP ELF only) */
#define SHT_SCE_PSPRELA		0x700000A0	/* Unused (PSP ELF only) */
#define SHT_SCE_ARMRELA		0x700000A4	/* Unused (PSP ELF only) */

/* SCE-specific definitions for p_type: */
#define PT_SCE_RELA		0x60000000	/* SCE Relocations */
#define PT_SCE_COMMENT		0x6FFFFF00	/* Unused */
#define PT_SCE_VERSION		0x6FFFFF01	/* Unused */
#define PT_SCE_UNK		0x70000001	/* Unknown */
#define PT_SCE_PSPRELA		0x700000A0	/* Unused (PSP ELF only) */
#define PT_SCE_PPURELA		0x700000A4	/* Unused (SPU ELF only) */

#define NID_MODULE_STOP		0x79F8E492
#define NID_MODULE_EXIT		0x913482A9
#define NID_MODULE_START	0x935CD196
#define NID_MODULE_INFO		0x6C2224BA
#define NID_PROCESS_PARAM	0x70FBA1E7

#ifndef R_ARM_NONE
#define R_ARM_NONE            0
#endif
#ifndef R_ARM_ABS32
#define R_ARM_ABS32           2
#endif

typedef union {
	Elf32_Word r_short : 4;
	struct {
		Elf32_Word r_short     : 4;
		Elf32_Word r_symseg    : 4;
		Elf32_Word r_code      : 8;
		Elf32_Word r_datseg    : 4;
		Elf32_Word r_offset_lo : 12;
		Elf32_Word r_offset_hi : 20;
		Elf32_Word r_addend    : 12;
	} r_short_entry;
	struct {
		Elf32_Word r_short     : 4;
		Elf32_Word r_symseg    : 4;
		Elf32_Word r_code      : 8;
		Elf32_Word r_datseg    : 4;
		Elf32_Word r_code2     : 8;
		Elf32_Word r_dist2     : 4;
		Elf32_Word r_addend;
		Elf32_Word r_offset;
	} r_long_entry;
	struct {
		Elf32_Word r_word1;
		Elf32_Word r_word2;
		Elf32_Word r_word3;
	} r_raw_entry;
} SCE_Rel;

#define SCE_ELF_DEFS_HOST
#include "sce-elf.h"
#undef SCE_ELF_DEFS_HOST

#define SCE_ELF_DEFS_TARGET
#include "sce-elf.h"
#undef SCE_ELF_DEFS_TARGET

/* This struct must only contain Elf32_Words, because we use it as an array in sce-elf.c */
typedef struct {
	Elf32_Word sceModuleInfo_rodata;	/* The sce_module_info structure */
	Elf32_Word sceLib_ent;			/* All sce_module_exports structures */
	Elf32_Word sceExport_rodata;		/* The tables referenced by sce_module_exports */
	Elf32_Word sceLib_stubs;		/* All sce_module_imports structures */
	Elf32_Word sceImport_rodata;		/* Misc data referenced by sce_module_imports */
	Elf32_Word sceFNID_rodata;		/* The imported function NID arrays */
	Elf32_Word sceFStub_rodata;		/* The imported function pointer arrays */
	Elf32_Word sceVNID_rodata;		/* The imported function NID arrays */
	Elf32_Word sceVStub_rodata;		/* The imported function NID arrays */
} sce_section_sizes_t;


#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <libelf.h>
#include <gelf.h>

#include "export.h"
#include "varray.h"

const uint32_t sce_elf_stub_func[4] = {
 0xe3e00000,	/* mvn r0, #0 */
 0xe12fff1e,	/* bx lr */
 0xe1a00000,	/* mov r0, r0 */
 0
};
const uint32_t sce_elf_stub_var[4] = {
 0, 0, 0, 0
};

#define ALIGN_4(size) (((size) + 3) & ~0x3)

typedef struct {
	uint32_t nid;
	vita_imports_module_t *module;

	union {
		vita_elf_stub_t *functions;
		varray functions_va;
	};

	union {
		vita_elf_stub_t *variables;
		varray variables_va;
	};
} import_module;

static int _stub_sort(const void *el1, const void *el2) {
	const vita_elf_stub_t *stub1 = el1, *stub2 = el2;
	if (stub2->target_nid > stub1->target_nid)
		return 1;
	else if (stub2->target_nid < stub1->target_nid)
		return -1;
	return 0;
}
static int _stub_nid_search(const void *key, const void *element) {
	const uint32_t *nid = key;
	const vita_elf_stub_t *stub = element;
	if (stub->target_nid > *nid)
		return 1;
	else if (stub->target_nid < *nid)
		return -1;
	return 0;
}

static void * _module_init(void *element) {
	import_module *module = element;
	if (!varray_init(&module->functions_va, sizeof(vita_elf_stub_t), 8)) return NULL;
	if (!varray_init(&module->variables_va, sizeof(vita_elf_stub_t), 4)) return NULL;

	module->functions_va.sort_compar = _stub_sort;
	module->functions_va.search_compar = _stub_nid_search;
	module->variables_va.sort_compar = _stub_sort;
	module->variables_va.search_compar = _stub_nid_search;

	return module;
}
static void _module_destroy(void *element) {
	import_module *module = element;
	varray_destroy(&module->functions_va);
	varray_destroy(&module->variables_va);
}

static int _module_sort(const void *el1, const void *el2) {
	const import_module *mod1 = el1, *mod2 = el2;
	if (mod2->nid > mod1->nid)
		return 1;
	else if (mod2->nid < mod1->nid)
		return -1;
	return 0;
}

static int _module_search(const void *key, const void *element) {
	const uint32_t *nid = key;
	const import_module *module = element;
	if (module->nid > *nid)
		return 1;
	else if (module->nid < *nid)
		return -1;
	return 0;
}

static int get_function_by_symbol(const char *symbol, vita_elf_t *ve, Elf32_Addr *vaddr) {
	for (int i = 0; i < ve->num_symbols; ++i) {
		if (ve->symtab[i].type == STT_FUNC && strcmp(ve->symtab[i].name, symbol) == 0) {
			*vaddr = ve->symtab[i].value;
			return 1;
		}
	}
	return 0;
}

static int get_variable_by_symbol(const char *symbol, vita_elf_t *ve, Elf32_Addr *vaddr) {
	for (int i = 0; i < ve->num_symbols; ++i) {
		if (ve->symtab[i].type == STT_OBJECT && strcmp(ve->symtab[i].name, symbol) == 0) {
			*vaddr = ve->symtab[i].value;
			return true;
		}
	}
	return false;
}

typedef union {
	import_module *modules;
	varray va;
} import_module_list;

static int set_module_export(vita_elf_t *ve, sce_module_exports_t *export, vita_library_export *lib) {
	export->size = sizeof(sce_module_exports_raw);
	export->version = 1;
	export->flags = lib->syscall ? 0x4001 : 0x0001;
	export->num_syms_funcs = lib->function_n;
	export->num_syms_vars = lib->variable_n;
	export->module_name = strdup(lib->name);
	export->module_nid = lib->nid;

	int total_exports = export->num_syms_funcs + export->num_syms_vars;
	export->nid_table = calloc(total_exports, sizeof(uint32_t));
	export->entry_table = calloc(total_exports, sizeof(void*));

	int cur_ent = 0;
	for (vita_export_symbol *sym = lib->functions; sym < lib->functions + export->num_syms_funcs; ++sym) {
		Elf32_Addr vaddr = 0;
		ASSERT(get_function_by_symbol(sym->name, ve, &vaddr), "Could not find function symbol '%s' for export '%s'", sym->name, lib->name);
		export->nid_table[cur_ent] = sym->nid;
		export->entry_table[cur_ent] = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_ent;
	}

	for (vita_export_symbol *sym = lib->variables; sym < lib->variables + export->num_syms_vars; ++sym ) {
		Elf32_Addr vaddr = 0;
		ASSERT(get_variable_by_symbol(sym->name, ve, &vaddr), "Could not find variable symbol '%s' for export '%s'", sym->name, lib->name);
		export->nid_table[cur_ent] = sym->nid;
		export->entry_table[cur_ent] = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_ent;
	}

	return 0;
	failure:
	return -1;
}

static int set_main_module_export(vita_elf_t *ve, sce_module_exports_t *export, sce_module_info_t *module_info, vita_export_t *export_spec) {
	export->size = sizeof(sce_module_exports_raw);
	export->version = 0;
	export->flags = 0x8000;
	export->num_syms_funcs = 1 + !!export_spec->stop + !!export_spec->exit;
	export->num_syms_vars = 2;

	int total_exports = export->num_syms_funcs + export->num_syms_vars;
	export->nid_table = calloc(total_exports, sizeof(uint32_t));
	export->entry_table = calloc(total_exports, sizeof(void*));

	int cur_nid = 0;

	if (export_spec->start) {
		Elf32_Addr vaddr = 0;
		ASSERT(get_function_by_symbol(export_spec->start, ve, &vaddr), "Could not find symbol '%s' for main export 'start'", export_spec->start);
		module_info->module_start = vita_elf_vaddr_to_host(ve, vaddr);
	} else
		module_info->module_start = vita_elf_vaddr_to_host(ve, elf32_getehdr(ve->elf)->e_entry);

	export->nid_table[cur_nid] = NID_MODULE_START;
	export->entry_table[cur_nid] = module_info->module_start;
	++cur_nid;

	if (export_spec->stop) {
		Elf32_Addr vaddr = 0;

		ASSERT(get_function_by_symbol(export_spec->stop, ve, &vaddr), "Could not find symbol '%s' for main export 'stop'", export_spec->stop);

		export->nid_table[cur_nid] = NID_MODULE_STOP;
		export->entry_table[cur_nid] = module_info->module_stop = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_nid;
	}

	if (export_spec->exit) {
		Elf32_Addr vaddr = 0;

		ASSERT(get_function_by_symbol(export_spec->exit, ve, &vaddr), "Could not find symbol '%s' for main export 'exit'", export_spec->exit);

		export->nid_table[cur_nid] = NID_MODULE_EXIT;
		export->entry_table[cur_nid] = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_nid;
	}

	export->nid_table[cur_nid] = NID_MODULE_INFO;
	export->entry_table[cur_nid] = module_info;
	++cur_nid;

	export->nid_table[cur_nid] = NID_PROCESS_PARAM;
	export->entry_table[cur_nid] = &module_info->process_param_size;
	++cur_nid;

	return 0;

	failure:
	return -1;
}

static void set_module_import(vita_elf_t *ve, sce_module_imports_t *import, const import_module *module) {
	import->size = sizeof(sce_module_imports_raw);
	import->version = 1;
	import->num_syms_funcs = module->functions_va.count;
	import->num_syms_vars = module->variables_va.count;
	import->module_nid = module->nid;
	import->flags = module->module->flags;
	import->module_name = module->module ? module->module->name : import->module_name;
	import->func_nid_table = calloc(module->functions_va.count, sizeof(uint32_t));
	import->func_entry_table = calloc(module->functions_va.count, sizeof(void *));
	for (int i = 0; i < module->functions_va.count; i++) {
		import->func_nid_table[i] = module->functions[i].target_nid;
		import->func_entry_table[i] = vita_elf_vaddr_to_host(ve, module->functions[i].addr);
	}
	import->var_nid_table = calloc(module->variables_va.count, sizeof(uint32_t));
	import->var_entry_table = calloc(module->variables_va.count, sizeof(void *));
	for (int i = 0; i < module->variables_va.count; i++) {
		import->var_nid_table[i] = module->variables[i].target_nid;
		import->var_entry_table[i] = vita_elf_vaddr_to_host(ve, module->variables[i].addr);
	}
}

void sce_elf_module_info_free(sce_module_info_t *module_info) {
	if (module_info == NULL)
		return;

	for (sce_module_exports_t *export = module_info->export_top; export < module_info->export_end; export++) {
		free(export->nid_table);
		free(export->entry_table);
	}
	free(module_info->export_top);

	for (sce_module_imports_t *import = module_info->import_top; import < module_info->import_end; import++) {
		free(import->func_nid_table);
		free(import->func_entry_table);
		free(import->var_nid_table);
		free(import->var_entry_table);
		free(import->unk_nid_table);
		free(import->unk_entry_table);
	}

	free(module_info->import_top);
	free(module_info);
}

sce_module_info_t *sce_elf_module_info_create(vita_elf_t *ve, vita_export_t *exports) {
	int i;
	sce_module_info_t *module_info;
	import_module_list modlist = {0};
	vita_elf_stub_t *curstub;
	import_module *curmodule;

	module_info = calloc(1, sizeof(sce_module_info_t));
	ASSERT(module_info != NULL);

	module_info->type = 6;
	module_info->version = (exports->ver_major << 8) | exports->ver_minor;

	strncpy(module_info->name, exports->name, sizeof(module_info->name) - 1);

	// allocate memory for all libraries + main
	module_info->export_top = calloc(exports->module_n + 1, sizeof(sce_module_exports_t));
	ASSERT(module_info->export_top != NULL);
	module_info->export_end = module_info->export_top + exports->module_n + 1;

	ASSERT(set_main_module_export(ve, module_info->export_top, module_info, exports) >= 0);

	// populate rest of exports
	for (i = 0; i < exports->module_n; ++i) {
		vita_library_export *lib = exports->modules[i];
		sce_module_exports_t *exp = (sce_module_exports_t *)(module_info->export_top + i + 1);

		// TODO: improve cleanup
		ASSERT(set_module_export(ve, exp, lib) >= 0);
	}

	ASSERT(varray_init(&modlist.va, sizeof(import_module), 8));
	modlist.va.init_func = _module_init;
	modlist.va.destroy_func = _module_destroy;
	modlist.va.sort_compar = _module_sort;
	modlist.va.search_compar = _module_search;

	for (i = 0; i < ve->num_fstubs; i++) {
		curstub = ve->fstubs + i;
		curmodule = varray_sorted_search_or_insert(&modlist.va, &curstub->module_nid, NULL);
		ASSERT(curmodule);
		curmodule->nid = curstub->module_nid;
		if (curstub->module)
			curmodule->module = curstub->module;

		varray_sorted_insert_ex(&curmodule->functions_va, curstub, 0);
	}

	for (i = 0; i < ve->num_vstubs; i++) {
		curstub = ve->vstubs + i;
		curmodule = varray_sorted_search_or_insert(&modlist.va, &curstub->module_nid, NULL);
		ASSERT(curmodule);
		curmodule->nid = curstub->module_nid;
		if (curstub->module)
			curmodule->module = curstub->module;

		varray_sorted_insert_ex(&curmodule->variables_va, curstub, 0);
	}

	module_info->import_top = calloc(modlist.va.count, sizeof(sce_module_imports_t));
	ASSERT(module_info->import_top != NULL);
	module_info->import_end = module_info->import_top + modlist.va.count;

	for (i = 0; i < modlist.va.count; i++) {
		set_module_import(ve, module_info->import_top + i, modlist.modules + i);
	}

	return module_info;

	failure:
	varray_destroy(&modlist.va);

	sce_failure:
	sce_elf_module_info_free(module_info);
	return NULL;
}

#define INCR(section, size) do { \
	sizes->section += (size); \
	total_size += (size); \
} while (0)
int sce_elf_module_info_get_size(sce_module_info_t *module_info, sce_section_sizes_t *sizes) {
	int total_size = 0;
	sce_module_exports_t *export;
	sce_module_imports_t *import;

	memset(sizes, 0, sizeof(*sizes));

	INCR(sceModuleInfo_rodata, sizeof(sce_module_info_raw));
	for (export = module_info->export_top; export < module_info->export_end; export++) {
		INCR(sceLib_ent, sizeof(sce_module_exports_raw));
		if (export->module_name != NULL) {
			INCR(sceExport_rodata, ALIGN_4(strlen(export->module_name) + 1));
		}
		INCR(sceExport_rodata, (export->num_syms_funcs + export->num_syms_vars + export->num_syms_unk) * 8);
	}

	for (import = module_info->import_top; import < module_info->import_end; import++) {
		INCR(sceLib_stubs, sizeof(sce_module_imports_raw));
		if (import->module_name != NULL) {
			INCR(sceImport_rodata, ALIGN_4(strlen(import->module_name) + 1));
		}
		INCR(sceFNID_rodata, import->num_syms_funcs * 4);
		INCR(sceFStub_rodata, import->num_syms_funcs * 4);
		INCR(sceVNID_rodata, import->num_syms_vars * 4);
		INCR(sceVStub_rodata, import->num_syms_vars * 4);
		INCR(sceImport_rodata, import->num_syms_unk * 8);
	}

	return total_size;
}
#undef INCR


#define INCR(section, size) do { \
	cur_sizes.section += (size); \
	ASSERT(cur_sizes.section <= sizes->section, "Attempted to overrun section %s!", #section); \
	section_addrs.section += (size); \
} while (0)
#define ADDR(section) (data + section_addrs.section)
#define INTADDR(section) (*((uint32_t *)ADDR(section)))
#define VADDR(section) (section_addrs.section + segment_base + start_offset)
#define OFFSET(section) (section_addrs.section + start_offset)
#define CONVERT(variable, member, conversion) variable ## _raw->member = conversion(variable->member)
#define CONVERT16(variable, member) CONVERT(variable, member, htole16)
#define CONVERT32(variable, member) CONVERT(variable, member, htole32)
#define CONVERTOFFSET(variable, member) variable ## _raw->member = htole32(vita_elf_host_to_segoffset(ve,variable->member,segndx))
#define SETLOCALPTR(variable, section) do { \
	variable = htole32(VADDR(section)); \
	ADDRELA(&variable); \
} while(0)
#define ADDRELA(localaddr) do { \
	uint32_t addend = le32toh(*((uint32_t *)localaddr)); \
	if (addend) { \
		vita_elf_rela_t *rela = varray_push(&relas, NULL); \
		rela->type = R_ARM_ABS32; \
		rela->offset = ((void*)(localaddr)) - data + segment_base + start_offset; \
		rela->addend = addend; \
	} \
} while(0)
void *sce_elf_module_info_encode(sce_module_info_t *module_info, vita_elf_t *ve, sce_section_sizes_t *sizes, vita_elf_rela_table_t *rtable) {
	void *data;
	sce_section_sizes_t cur_sizes = {0};
	sce_section_sizes_t section_addrs = {0};
	int total_size = 0;
	Elf32_Addr segment_base;
	Elf32_Word start_offset;
	int segndx;
	int i;
	sce_module_exports_t *export;
	sce_module_imports_t *import;
	sce_module_info_raw *module_info_raw;
	sce_module_exports_raw *export_raw;
	sce_module_imports_raw *import_raw;
	varray relas;

	ASSERT(varray_init(&relas, sizeof(vita_elf_rela_t), 16));

	for (i = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		((Elf32_Word *)&section_addrs)[i] = total_size;
		total_size += ((Elf32_Word *)sizes)[i];
	}

	segndx = vita_elf_host_to_segndx(ve, module_info->module_start);

	segment_base = ve->segments[segndx].vaddr;
	start_offset = ve->segments[segndx].memsz;
	start_offset = (start_offset + 0xF) & ~0xF; // align to 16 bytes

	for (i = 0; i < ve->num_segments; i++) {
		if (i == segndx)
			continue;
		int pos = ve->segments[i].vaddr - segment_base - start_offset;
		ASSERT((pos < 0) || (pos >= total_size), "Cannot allocate %d bytes for SCE data at end of segment %d; segment %d overlaps", total_size, segndx, i)
	}

	data = calloc(1, total_size);
	ASSERT(data != NULL);

	module_info_raw = (sce_module_info_raw *)ADDR(sceModuleInfo_rodata);
	INCR(sceModuleInfo_rodata, sizeof(sce_module_info_raw));
	CONVERT16(module_info, attributes);
	CONVERT16(module_info, version);
	memcpy(module_info_raw->name, module_info->name, 27);
	module_info_raw->type = module_info->type;
	module_info_raw->export_top = htole32(OFFSET(sceLib_ent));
	module_info_raw->export_end = htole32(OFFSET(sceLib_ent) + sizes->sceLib_ent);
	module_info_raw->import_top = htole32(OFFSET(sceLib_stubs));
	module_info_raw->import_end = htole32(OFFSET(sceLib_stubs) + sizes->sceLib_stubs);
	CONVERT32(module_info, library_nid);
	CONVERT32(module_info, field_38);
	CONVERT32(module_info, field_3C);
	CONVERT32(module_info, field_40);
	CONVERTOFFSET(module_info, module_start);
	CONVERTOFFSET(module_info, module_stop);
	CONVERTOFFSET(module_info, exidx_top);
	CONVERTOFFSET(module_info, exidx_end);
	CONVERTOFFSET(module_info, extab_top);
	CONVERTOFFSET(module_info, extab_end);
	module_info_raw->process_param_size = 0x34;
	memcpy(&module_info_raw->process_param_magic, "PSP2", 4);

	for (export = module_info->export_top; export < module_info->export_end; export++) {
		int num_syms;
		uint32_t *raw_nids, *raw_entries;

		export_raw = (sce_module_exports_raw *)ADDR(sceLib_ent);
		INCR(sceLib_ent, sizeof(sce_module_exports_raw));

		export_raw->size = htole16(sizeof(sce_module_exports_raw));
		CONVERT16(export, version);
		CONVERT16(export, flags);
		CONVERT16(export, num_syms_funcs);
		CONVERT32(export, num_syms_vars);
		CONVERT32(export, num_syms_unk);
		CONVERT32(export, module_nid);
		if (export->module_name != NULL) {
			SETLOCALPTR(export_raw->module_name, sceExport_rodata);
			void *dst = ADDR(sceExport_rodata);
			INCR(sceExport_rodata, ALIGN_4(strlen(export->module_name) + 1));
			strcpy(dst, export->module_name);
		}
		num_syms = export->num_syms_funcs + export->num_syms_vars + export->num_syms_unk;
		SETLOCALPTR(export_raw->nid_table, sceExport_rodata);
		raw_nids = (uint32_t *)ADDR(sceExport_rodata);
		INCR(sceExport_rodata, num_syms * 4);
		SETLOCALPTR(export_raw->entry_table, sceExport_rodata);
		raw_entries = (uint32_t *)ADDR(sceExport_rodata);
		INCR(sceExport_rodata, num_syms * 4);
		for (i = 0; i < num_syms; i++) {
			raw_nids[i] = htole32(export->nid_table[i]);
			if (export->entry_table[i] == module_info) { /* Special case */
				raw_entries[i] = htole32(segment_base + start_offset);
			} else if (export->entry_table[i] == &module_info->process_param_size) {
				raw_entries[i] = htole32(segment_base + start_offset + offsetof(sce_module_info_raw, process_param_size));
			} else {
				raw_entries[i] = htole32(vita_elf_host_to_vaddr(ve, export->entry_table[i]));
			}
			ADDRELA(raw_entries + i);
		}
	}

	for (import = module_info->import_top; import < module_info->import_end; import++) {
		import_raw = (sce_module_imports_raw *)ADDR(sceLib_stubs);
		INCR(sceLib_stubs, sizeof(sce_module_imports_raw));

		import_raw->size = htole16(sizeof(sce_module_imports_raw));
		CONVERT16(import, version);
		CONVERT16(import, flags);
		CONVERT16(import, num_syms_funcs);
		CONVERT16(import, num_syms_vars);
		CONVERT16(import, num_syms_unk);
		CONVERT32(import, reserved1);
		CONVERT32(import, reserved2);
		CONVERT32(import, module_nid);

		if (import->module_name != NULL) {
			SETLOCALPTR(import_raw->module_name, sceImport_rodata);
			void *dst = ADDR(sceImport_rodata);
			INCR(sceImport_rodata, ALIGN_4(strlen(import->module_name) + 1));
			strcpy(dst, import->module_name);
		}
		if (import->num_syms_funcs) {
			SETLOCALPTR(import_raw->func_nid_table, sceFNID_rodata);
			SETLOCALPTR(import_raw->func_entry_table, sceFStub_rodata);
			for (i = 0; i < import->num_syms_funcs; i++) {
				INTADDR(sceFNID_rodata) = htole32(import->func_nid_table[i]);
				INTADDR(sceFStub_rodata) = htole32(vita_elf_host_to_vaddr(ve, import->func_entry_table[i]));
				ADDRELA(ADDR(sceFStub_rodata));
				INCR(sceFNID_rodata, 4);
				INCR(sceFStub_rodata, 4);
			}
		}
		if (import->num_syms_vars) {
			SETLOCALPTR(import_raw->var_nid_table, sceVNID_rodata);
			SETLOCALPTR(import_raw->var_entry_table, sceVStub_rodata);
			for (i = 0; i < import->num_syms_vars; i++) {
				INTADDR(sceVNID_rodata) = htole32(import->var_nid_table[i]);
				INTADDR(sceVStub_rodata) = htole32(vita_elf_host_to_vaddr(ve, import->var_entry_table[i]));
				ADDRELA(ADDR(sceVStub_rodata));
				INCR(sceVNID_rodata, 4);
				INCR(sceVStub_rodata, 4);
			}
		}
		if (import->num_syms_unk) {
			SETLOCALPTR(import_raw->unk_nid_table, sceImport_rodata);
			for (i = 0; i < import->num_syms_unk; i++) {
				INTADDR(sceImport_rodata) = htole32(import->var_nid_table[i]);
				INCR(sceImport_rodata, 4);
			}
			SETLOCALPTR(import_raw->unk_entry_table, sceImport_rodata);
			for (i = 0; i < import->num_syms_unk; i++) {
				INTADDR(sceImport_rodata) = htole32(vita_elf_host_to_vaddr(ve, import->var_entry_table[i]));
				ADDRELA(ADDR(sceImport_rodata));
				INCR(sceImport_rodata, 4);
			}
		}
	}

	for (i = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		ASSERT((((Elf32_Word *)&cur_sizes)[i] == ((Elf32_Word *)sizes)[i]), "remaining space in section %d!", i);
	}

	rtable->num_relas = relas.count;
	rtable->relas = varray_extract_array(&relas);

	return data;
	failure:
	free(data);
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

int elf_utils_shift_contents(Elf *e, int start_offset, int shift_amount) {
	GElf_Ehdr ehdr;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t segment_count = 0, segndx;
	GElf_Phdr phdr;
	int bottom_section_offset = 0;
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


Elf_Scn *elf_utils_new_scn_with_name(Elf *e, const char *scn_name) {
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t shstrndx, index, namelen;
	Elf_Data *shstrdata;
	void *ptr;

	ELF_ASSERT(!elf_getshdrstrndx(e, &shstrndx));

	ELF_ASSERT(scn = elf_getscn(e, shstrndx));
	char * str = elf_strptr(e, shstrndx, 0);
	ELF_ASSERT(shstrdata = elf_getdata(scn, NULL));

	namelen = strlen(scn_name) + 1;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	ASSERT(elf_utils_shift_contents(e, shdr.sh_offset + shdr.sh_size, namelen));
	ASSERT(ptr = realloc(shstrdata->d_buf, shstrdata->d_size + namelen));
	index = shstrdata->d_size;
	strcpy(ptr+index, scn_name);
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

int sce_elf_write_module_info(Elf *dest, vita_elf_t *ve, sce_section_sizes_t *sizes, void *module_info) {
	/* Corresponds to the order in sce_section_sizes_t */
	static const char *section_names[] = {
	 ".sceModuleInfo.rodata",
	 ".sceLib.ent",
	 ".sceExport.rodata",
	 ".sceLib.stubs",
	 ".sceImport.rodata",
	 ".sceFNID.rodata",
	 ".sceFStub.rodata",
	 ".sceVNID.rodata",
	 ".sceVStub.rodata"
	};
	sce_section_sizes_t section_addrs = {0};
	int total_size = 0;
	for (size_t i = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		((Elf32_Word *)&section_addrs)[i] = total_size;
		total_size += ((Elf32_Word *)sizes)[i];
	}

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(dest, &ehdr));

	int segndx;
	for (segndx = 0; segndx < ve->num_segments; segndx++) {
		if (ehdr.e_entry >= ve->segments[segndx].vaddr
		    && ehdr.e_entry < ve->segments[segndx].vaddr + ve->segments[segndx].memsz) {
			break;
		}
	}
	ASSERT(segndx < ve->num_segments);

	GElf_Phdr phdr;
	ELF_ASSERT(gelf_getphdr(dest, segndx, &phdr));

	Elf32_Addr segment_base = ve->segments[segndx].vaddr;
	Elf32_Word start_segoffset = ve->segments[segndx].memsz;
	start_segoffset = (start_segoffset + 0xF) & ~0xF; // align to 16 bytes, same with `sce_elf_module_info_encode`
	total_size += (start_segoffset - ve->segments[segndx].memsz); // add the padding size

	Elf32_Addr start_vaddr = segment_base + start_segoffset;
	Elf32_Word start_foffset = phdr.p_offset + start_segoffset;

	ASSERT(elf_utils_shift_contents(dest, start_foffset, total_size), "Unable to relocate ELF sections\n")

	/* Extend in our copy of phdrs so that vita_elf_vaddr_to_segndx can match it */
	ve->segments[segndx].memsz += total_size;

	phdr.p_filesz += total_size;
	phdr.p_memsz += total_size;
	ELF_ASSERT(gelf_update_phdr(dest, segndx, &phdr));

	ELF_ASSERT(gelf_getehdr(dest, &ehdr));
	ehdr.e_entry = ((segndx & 0x3) << 30) | start_segoffset;
	ELF_ASSERT(gelf_update_ehdr(dest, &ehdr));

	for (size_t i = 0, cur_pos = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		int scn_size = ((Elf32_Word *)sizes)[i];
		if (scn_size == 0)
			continue;

		Elf_Scn *scn = elf_utils_new_scn_with_name(dest, section_names[i]);
		GElf_Shdr shdr;
		ELF_ASSERT(gelf_getshdr(scn, &shdr));
		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
		shdr.sh_addr = start_vaddr + cur_pos;
		shdr.sh_offset = start_foffset + cur_pos;
		shdr.sh_size = scn_size;
		shdr.sh_addralign = 4;
		ELF_ASSERT(gelf_update_shdr(scn, &shdr));

		Elf_Data *data;
		ELF_ASSERT(data = elf_newdata(scn));
		data->d_buf = module_info + cur_pos;
		data->d_type = ELF_T_BYTE;
		data->d_version = EV_CURRENT;
		data->d_size = scn_size;
		data->d_off = 0;
		data->d_align = 1;

		cur_pos += scn_size;
	}

	return 1;
	failure:
	return 0;
}

static int sce_rel_short(SCE_Rel *rel, int symseg, int code, int datseg, int offset, int addend) {
	if (addend > 1 << 11)
		return 0;
	rel->r_short_entry.r_short = 1;
	rel->r_short_entry.r_symseg = symseg;
	rel->r_short_entry.r_code = code;
	rel->r_short_entry.r_datseg = datseg;
	rel->r_short_entry.r_offset_lo = offset & 0xFFF;
	rel->r_short_entry.r_offset_hi = offset >> 20;
	rel->r_short_entry.r_addend = addend;
	return 1;
}

static int sce_rel_long(SCE_Rel *rel, int symseg, int code, int datseg, int offset, int addend) {
	rel->r_long_entry.r_short = 0;
	rel->r_long_entry.r_symseg = symseg;
	rel->r_long_entry.r_code = code;
	rel->r_long_entry.r_datseg = datseg;
	rel->r_long_entry.r_code2 = 0;
	rel->r_long_entry.r_dist2 = 0;
	rel->r_long_entry.r_offset = offset;
	rel->r_long_entry.r_addend = addend;
	return 1;
}

static int encode_sce_rel(SCE_Rel *rel) {
	if (rel->r_short_entry.r_short) {
		rel->r_raw_entry.r_word1 = htole32(
		 (rel->r_short_entry.r_short) |
		 (rel->r_short_entry.r_symseg << 4) |
		 (rel->r_short_entry.r_code << 8) |
		 (rel->r_short_entry.r_datseg << 16) |
		 (rel->r_short_entry.r_offset_lo << 20));
		rel->r_raw_entry.r_word2 = htole32(
		 (rel->r_short_entry.r_offset_hi) |
		 (rel->r_short_entry.r_addend << 20));
		return 8;
	} else {
		rel->r_raw_entry.r_word1 = htole32(
		 (rel->r_long_entry.r_short) |
		 (rel->r_long_entry.r_symseg << 4) |
		 (rel->r_long_entry.r_code << 8) |
		 (rel->r_long_entry.r_datseg << 16) |
		 (rel->r_long_entry.r_code2 << 20) |
		 (rel->r_long_entry.r_dist2 << 28));
		rel->r_raw_entry.r_word2 = htole32(rel->r_long_entry.r_addend);
		rel->r_raw_entry.r_word3 = htole32(rel->r_long_entry.r_offset);
		return 12;
	}
}

/* We have to check all relocs. If any of the point to a space in ELF that is not contained in any segment,
 * we should discard this reloc. This should be done before we extend the code segment with modinfo, because otherwise
 * the invalid addresses may become valid */
int sce_elf_discard_invalid_relocs(const vita_elf_t *ve, vita_elf_rela_table_t *rtable) {
	vita_elf_rela_table_t *curtable;
	vita_elf_rela_t *vrela;
	int i, datseg;
	for (curtable = rtable; curtable; curtable = curtable->next) {
		for (i = 0, vrela = curtable->relas; i < curtable->num_relas; i++, vrela++) {
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
			/* We can get -1 here for some debugging-related relocations.
			 * These are done against debug sections that aren't mapped to any segment.
			 * Just ignore these */
			if (datseg == -1)
				vrela->type = R_ARM_NONE;
		}
	}
	return 1;
}

Elf_Scn *elf_utils_new_scn_with_data(Elf *e, const char *scn_name, void *buf, int len) {
	Elf_Scn *scn = elf_utils_new_scn_with_name(e, scn_name);
	ASSERT(scn != NULL);

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	int offset = ehdr.e_shoff;
	ASSERT(elf_utils_shift_contents(e, offset, len + 0x10));

	GElf_Shdr shdr;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_offset = (offset + 0x10) & ~0xF;
	shdr.sh_size = len;
	shdr.sh_addralign = 1;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	Elf_Data *data;
	ELF_ASSERT(data = elf_newdata(scn));
	data->d_buf = buf;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	data->d_size = len;
	data->d_off = 0;
	data->d_align = 1;

	return scn;
	failure:
	return NULL;
}

int sce_elf_write_rela_sections(Elf *dest, vita_elf_t *ve, vita_elf_rela_table_t *rtable) {
	int (*sce_rel_func)(SCE_Rel *, int, int, int, int, int) = sce_rel_long; // sce_rel_short
	int total_relas = 0;
	for (vita_elf_rela_table_t *curtable = rtable; curtable; curtable = curtable->next) {
		total_relas += curtable->num_relas;
	}

	void* curpos, *encoded_relas = calloc(total_relas, 12);
	ASSERT(encoded_relas);
	encode_relas:
	curpos = encoded_relas;
	for (vita_elf_rela_table_t *curtable = rtable; curtable; curtable = curtable->next) {
		for (vita_elf_rela_t *vrela = curtable->relas; vrela < (curtable->relas + curtable->num_relas); vrela++) {
			if (vrela->type == R_ARM_NONE)
				continue;
			Elf32_Word datseg = vita_elf_vaddr_to_segndx(ve, vrela->offset);
			Elf32_Word datoff = vita_elf_vaddr_to_segoffset(ve, vrela->offset, datseg);
			Elf32_Addr symvaddr = vrela->symbol ? vrela->symbol->value + vrela->addend : vrela->addend;
			Elf32_Word symseg = vita_elf_vaddr_to_segndx(ve, vrela->symbol ? vrela->symbol->value : vrela->addend);
			if (symseg == -1)
				continue;
			SCE_Rel rel;
			Elf32_Word symoff = vita_elf_vaddr_to_segoffset(ve, symvaddr, symseg);
			if (!sce_rel_func(&rel, symseg, vrela->type, datseg, datoff, symoff)) {
				sce_rel_func = sce_rel_long;
				goto encode_relas;
			}
			int relsz = encode_sce_rel(&rel);
			memcpy(curpos, &rel, relsz);
			curpos += relsz;
		}
	}
	Elf_Scn *scn = elf_utils_new_scn_with_data(dest, ".sce.rel", encoded_relas, curpos - encoded_relas);
	if (scn == NULL)
		goto failure;
	encoded_relas = NULL;

	GElf_Shdr shdr;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_type = SHT_SCE_RELA;
	shdr.sh_flags = 0;
	shdr.sh_addralign = 4;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	size_t segment_count = 0;
	ELF_ASSERT((elf_getphdrnum(dest, &segment_count), segment_count > 0));
	GElf_Phdr *phdrs = calloc(segment_count + 1, sizeof(GElf_Phdr));
	ASSERT(phdrs);
	for (int i = 0; i < segment_count; i++) {
		ELF_ASSERT(gelf_getphdr(dest, i, phdrs + i));
	}
	ELF_ASSERT(gelf_newphdr(dest, segment_count + 1));
	ELF_ASSERT(gelf_getphdr(dest, segment_count, phdrs + segment_count));
	phdrs[segment_count].p_type = PT_SCE_RELA;
	phdrs[segment_count].p_offset = shdr.sh_offset;
	phdrs[segment_count].p_filesz = shdr.sh_size;
	phdrs[segment_count].p_align = 16;
	for (int i = 0; i < segment_count + 1; i++) {
		ELF_ASSERT(gelf_update_phdr(dest, i, phdrs + i));
	}

	return 1;

	failure:
	free(encoded_relas);
	return 0;
}

int sce_elf_rewrite_stub(Elf *dest, void *shstrtab, const varray* va, char* sec_name, char* sec_fmt, const uint32_t*stub) {
	for(int j = 0; j < va->count; j++){
		int *cur_ndx = VARRAY_ELEMENT(va,j);
		Elf_Scn *scn;
		GElf_Shdr shdr;
		ELF_ASSERT(scn = elf_getscn(dest, *cur_ndx));
		ELF_ASSERT(gelf_getshdr(scn, &shdr));

		char *sh_name = shstrtab + shdr.sh_name;
		if (strstr(sh_name, sec_name) != sh_name)
			return fprintf(stderr, "Malformed %s section.", sec_name), 0;
		char *stub_name = strrchr(sh_name, '.');
		snprintf(sh_name, strlen(sh_name) + 1, sec_fmt, stub_name);

		for (Elf_Data *data = NULL; (data = elf_getdata(scn, data)); ) {
			for (uint32_t *stubdata = (uint32_t *)data->d_buf; (void *)stubdata < data->d_buf + data->d_size - 11; stubdata += 4) {
				stubdata[0] = htole32(stub[0]);
				stubdata[1] = htole32(stub[1]);
				stubdata[2] = htole32(stub[2]);
				stubdata[3] = htole32(stub[3]);
			}
		}
	}
	return 1;
	failure:
	return 0;
}

int sce_elf_rewrite_stubs(Elf *dest, const vita_elf_t *ve) {
	size_t shstrndx;
	ELF_ASSERT(elf_getshdrstrndx(dest, &shstrndx) == 0);
	Elf_Scn *scn = elf_getscn(dest, shstrndx);
	ELF_ASSERT(scn);
	Elf_Data *data = elf_getdata(scn, NULL);
	ELF_ASSERT(data);

	sce_elf_rewrite_stub(dest, data->d_buf, &ve->fstubs_va, ".vitalink.fstubs.", ".text.fstubs%s", sce_elf_stub_func);
	sce_elf_rewrite_stub(dest, data->d_buf, &ve->vstubs_va, ".vitalink.vstubs.", ".data.vstubs%s", sce_elf_stub_var);

	return 1;
	failure:
	return 0;
}

#endif
