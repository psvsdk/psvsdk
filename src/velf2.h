#ifndef VITA_ELF_H
#define VITA_ELF_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <unistd.h>

#include "varray.h"

#define ASSERT(cond, fmt...)                                \
	if (!(cond - 0)) {                                  \
		fprintf(stderr, "Failure:" #cond "\n" fmt); \
		goto failure;                               \
	}
#define ELF_ASSERT(cond) ASSERT((cond) != 0, "[%i] %s\n", elf_errno(), elf_errmsg(elf_errno()))

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

vita_imports_t* vita_imports_new(int n_libs) {
	vita_imports_t* imp = malloc(sizeof(*imp));
	if (imp == NULL)
		return NULL;
	imp->n_libs = n_libs;
	imp->libs   = calloc(n_libs, sizeof(*imp->libs));
	return imp;
}

void vita_imports_stub_free(vita_imports_stub_t* stub) {
	if (!stub)
		return;
	free(stub->name);
	free(stub);
}

void vita_imports_module_free(vita_imports_module_t* mod) {
	if (!mod)
		return;
	for (int i = 0; i < mod->n_variables; i++) {
		vita_imports_stub_free(mod->variables[i]);
	}
	for (int i = 0; i < mod->n_functions; i++) {
		vita_imports_stub_free(mod->functions[i]);
	}
	free(mod->name);
	free(mod);
}

void vita_imports_lib_free(vita_imports_lib_t* lib) {
	if (!lib)
		return;
	for (int i = 0; i < lib->n_modules; i++) {
		vita_imports_module_free(lib->modules[i]);
	}
	free(lib->name);
	free(lib);
}

void vita_imports_free(vita_imports_t* imp) {
	if (!imp)
		return;
	for (int i = 0; i < imp->n_libs; i++) {
		vita_imports_lib_free(imp->libs[i]);
	}
	free(imp);
}

vita_imports_lib_t* vita_imports_lib_new(const char* name, uint32_t NID, int n_modules) {
	vita_imports_lib_t* lib = malloc(sizeof(*lib));
	if (lib == NULL)
		return NULL;
	lib->name      = strdup(name);
	lib->NID       = NID;
	lib->n_modules = n_modules;
	lib->modules   = calloc(n_modules, sizeof(*lib->modules));
	return lib;
}

vita_imports_module_t* vita_imports_module_new(const char* name, bool kernel, uint32_t NID, int n_functions, int n_variables) {
	vita_imports_module_t* mod = malloc(sizeof(*mod));
	if (mod == NULL)
		return NULL;
	mod->name        = strdup(name);
	mod->NID         = NID;
	mod->is_kernel   = kernel;
	mod->n_functions = n_functions;
	mod->n_variables = n_variables;
	mod->functions   = calloc(n_functions, sizeof(*mod->functions));
	mod->variables   = calloc(n_variables, sizeof(*mod->variables));
	return mod;
}

vita_imports_stub_t* vita_imports_stub_new(const char* name, uint32_t NID) {
	vita_imports_stub_t* stub = malloc(sizeof(*stub));
	if (stub == NULL)
		return NULL;
	stub->name = strdup(name);
	stub->NID  = NID;
	return stub;
}

static vita_imports_common_fields* generic_find(vita_imports_common_fields** entries, int n_entries, uint32_t NID) {
	for (int i = 0; i < n_entries; i++) {
		if (entries[i] && entries[i]->NID == NID)
			return entries[i];
	}
	return NULL;
}

vita_imports_lib_t* vita_imports_find_lib(vita_imports_t* imp, uint32_t NID) {
	return (vita_imports_lib_t*)generic_find((vita_imports_common_fields**)imp->libs, imp->n_libs, NID);
}
vita_imports_module_t* vita_imports_find_module(vita_imports_lib_t* lib, uint32_t NID) {
	return (vita_imports_module_t*)generic_find((vita_imports_common_fields**)lib->modules, lib->n_modules, NID);
}
vita_imports_stub_t* vita_imports_find_function(vita_imports_module_t* mod, uint32_t NID) {
	return (vita_imports_stub_t*)generic_find((vita_imports_common_fields**)mod->functions, mod->n_functions, NID);
}
vita_imports_stub_t* vita_imports_find_variable(vita_imports_module_t* mod, uint32_t NID) {
	return (vita_imports_stub_t*)generic_find((vita_imports_common_fields**)mod->variables, mod->n_variables, NID);
}

/* Convenience representation of a symtab entry */
typedef struct vita_elf_symbol_t {
	const char* name;
	Elf32_Addr  value;
	uint8_t     type;
	uint8_t     binding;
	int         shndx;
} vita_elf_symbol_t;

typedef struct vita_elf_rela_t {
	uint8_t            type;
	vita_elf_symbol_t* symbol;
	Elf32_Addr         offset;
	Elf32_Sword        addend;
} vita_elf_rela_t;

typedef struct vita_elf_rela_table_t {
	vita_elf_rela_t* relas;
	int              num_relas;

	int target_ndx;

	struct vita_elf_rela_table_t* next;
} vita_elf_rela_table_t;

typedef struct vita_elf_stub_t {
	Elf32_Addr addr;
	uint32_t   module_nid;
	uint32_t   target_nid;

	vita_elf_symbol_t* symbol;

	vita_imports_module_t* module;
	vita_imports_stub_t*   target;
} vita_elf_stub_t;

typedef struct vita_elf_segment_info_t {
	Elf32_Word type;  /* Segment type */
	Elf32_Addr vaddr; /* Top of segment space on TARGET */
	Elf32_Word memsz; /* Size of segment space */

	/* vaddr_top/vaddr_bottom point to a reserved, unallocated memory space that
	 * represents the segment space in the HOST.  This space can be used as
	 * pointer targets for translated data structures. */
	const void* vaddr_top;
	const void* vaddr_bottom;
} vita_elf_segment_info_t;

typedef struct vita_elf_t {
	void*  file;
	size_t size;
	int    mode;
	Elf*   elf;

	varray fstubs_va;
	varray vstubs_va;

	int                symtab_ndx;
	vita_elf_symbol_t* symtab;
	int                num_symbols;

	vita_elf_rela_table_t* rela_tables;

	vita_elf_stub_t* fstubs;
	vita_elf_stub_t* vstubs;
	int              num_fstubs;
	int              num_vstubs;

	vita_elf_segment_info_t* segments;
	int                      num_segments;
} vita_elf_t;

static void free_rela_table(vita_elf_rela_table_t* rtable);

static int load_stubs(Elf_Scn* scn, int* num_stubs, vita_elf_stub_t** stubs, char* name) {
	GElf_Shdr        shdr;
	Elf_Data*        data;
	uint32_t*        stub_data;
	int              chunk_offset, total_bytes;
	vita_elf_stub_t* curstub;
	int              old_num;

	gelf_getshdr(scn, &shdr);

	old_num    = *num_stubs;
	*num_stubs = old_num + shdr.sh_size / 16;
	*stubs     = realloc(*stubs, *num_stubs * sizeof(vita_elf_stub_t));
	memset(&(*stubs)[old_num], 0, sizeof(vita_elf_stub_t) * shdr.sh_size / 16);

	name = strrchr(name, '.') + 1;

	curstub = *stubs;
	curstub = &curstub[*num_stubs - (shdr.sh_size / 16)];

	data        = NULL;
	total_bytes = 0;
	while (total_bytes < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {

		for (stub_data = (uint32_t*)data->d_buf, chunk_offset = 0; chunk_offset < data->d_size; stub_data += 4, chunk_offset += 16) {
			curstub->addr          = shdr.sh_addr + data->d_off + chunk_offset;
			curstub->module        = vita_imports_module_new(name, false, 0, 0, 0);
			curstub->module->flags = le32toh(stub_data[0]);
			curstub->module_nid    = le32toh(stub_data[1]);
			curstub->target_nid    = le32toh(stub_data[2]);
			curstub++;
		}

		total_bytes += data->d_size;
	}

	return 1;
}

static int load_symbols(vita_elf_t* ve, Elf_Scn* scn) {
	GElf_Shdr          shdr;
	Elf_Data*          data;
	GElf_Sym           sym;
	int                total_bytes;
	int                data_beginsym, symndx;
	vita_elf_symbol_t* cursym;

	if (elf_ndxscn(scn) == ve->symtab_ndx)
		return 1; /* Already loaded */

	ASSERT(ve->symtab == NULL, "ELF file appears to have multiple symbol tables!");

	gelf_getshdr(scn, &shdr);

	ve->num_symbols = shdr.sh_size / shdr.sh_entsize;
	ve->symtab      = calloc(ve->num_symbols, sizeof(vita_elf_symbol_t));
	ve->symtab_ndx  = elf_ndxscn(scn);

	data        = NULL;
	total_bytes = 0;
	while (total_bytes < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {

		data_beginsym = data->d_off / shdr.sh_entsize;
		for (symndx = 0; symndx < data->d_size / shdr.sh_entsize; symndx++) {
			ELF_ASSERT(gelf_getsym(data, symndx, &sym) == &sym);
			cursym          = ve->symtab + symndx + data_beginsym;
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
	case R_ARM_MOVW_ABS_NC: // movw
		return ((data & 0xf0000) >> 4) | (data & 0xfff);
	case R_ARM_MOVT_ABS: // movt
		return (((data & 0xf0000) >> 4) | (data & 0xfff)) << 16;
	case R_ARM_THM_MOVW_ABS_NC: // MOVW (THUMB)
		data = THUMB_SHUFFLE(data);
		return (((data >> 16) & 0xf) << 12) | (((data >> 26) & 0x1) << 11) | (((data >> 12) & 0x7) << 8) | (data & 0xff);
	case R_ARM_THM_MOVT_ABS: // MOVT (THUMB)
		data = THUMB_SHUFFLE(data);
		return (((data >> 16) & 0xf) << 28) | (((data >> 26) & 0x1) << 27) | (((data >> 12) & 0x7) << 24) | ((data & 0xff) << 16);
	}

	fprintf(stderr, "Invalid relocation type: %d", type);
	return ~0;
}

#define REL_HANDLE_NORMAL 0
#define REL_HANDLE_IGNORE -1
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

static int load_rel_table(vita_elf_t* ve, Elf_Scn* scn) {
	GElf_Shdr shdr, text_shdr;
	gelf_getshdr(scn, &shdr);

	ASSERT(load_symbols(ve, elf_getscn(ve->elf, shdr.sh_link)));

	vita_elf_rela_table_t* rtable = calloc(1, sizeof(vita_elf_rela_table_t));
	ASSERT(rtable != NULL);
	rtable->num_relas = shdr.sh_size / shdr.sh_entsize;
	rtable->relas     = calloc(rtable->num_relas, sizeof(vita_elf_rela_t));
	ASSERT(rtable->relas != NULL);

	rtable->target_ndx = shdr.sh_info;
	Elf_Scn* text_scn  = elf_getscn(ve->elf, shdr.sh_info);
	gelf_getshdr(text_scn, &text_shdr);
	Elf_Data* text_data = elf_getdata(text_scn, NULL);

	/* We're blatantly assuming here that both of these sections will store
	 * the entirety of their data in one Elf_Data item.  This seems to be true
	 * so far in my testing, and from the libelf source it looks like it's
	 * unlikely to allocate multiple data items on initial file read, but
	 * should be fixed someday. */
	Elf_Data* data = elf_getdata(scn, NULL);
	for (int relndx = 0; relndx < data->d_size / shdr.sh_entsize; relndx++) {
		GElf_Rel rel;
		uint32_t insn, target = 0;
		ASSERT(gelf_getrel(data, relndx, &rel) == &rel);

		vita_elf_rela_t* currela = rtable->relas + relndx;
		currela->type            = GELF_R_TYPE(rel.r_info);
		/* R_ARM_THM_JUMP24 is functionally the same as R_ARM_THM_CALL, however Vita only supports the second
		 * one */
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

		int handling = get_rel_handling(currela->type);

		if (handling == REL_HANDLE_IGNORE)
			continue;
		ASSERT(handling != REL_HANDLE_INVALID, "Invalid relocation type %d!", currela->type);

		int rel_sym = GELF_R_SYM(rel.r_info);
		ASSERT(rel_sym < ve->num_symbols, "REL entry tried to access symbol %d, but only %d symbols loaded", rel_sym, ve->num_symbols);

		currela->symbol = ve->symtab + rel_sym;

		ASSERT((target = decode_rel_target(insn, currela->type, rel.r_offset)) != ~0);

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

static int load_rela_table(vita_elf_t* ve, Elf_Scn* scn) {
	fprintf(stderr, "RELA sections currently unsupported");
	return 0;
}
const char* elf_decode_st_type(int st_type) {
	switch (st_type) {
#define STT(name)        \
	case STT_##name: \
		return #name
		STT(NOTYPE);
		STT(OBJECT);
		STT(FUNC);
		STT(SECTION);
		STT(FILE);
		STT(COMMON);
		STT(TLS);
		STT(NUM);
#undef STT
	}
	if (st_type >= STT_LOOS && st_type <= STT_HIOS)
		return "(OS-specific)";
	if (st_type >= STT_LOPROC && st_type <= STT_HIPROC)
		return "(Processor-specific)";
	return "(unknown)";
}
static int lookup_stub_symbols(vita_elf_t* ve, int num_stubs, vita_elf_stub_t* stubs, varray* stubs_va, int sym_type) {
	int                symndx;
	vita_elf_symbol_t* cursym;
	int                stub, stubs_ndx, i, *cur_ndx;
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
		ASSERT(cursym->type == sym_type, "Global symbol %s in section %d expected to have type %s; instead has type %s", cursym->name, stubs_ndx,
		       elf_decode_st_type(sym_type), elf_decode_st_type(cursym->type));
		for (stub = 0; stub < num_stubs; stub++) {
			if (stubs[stub].addr != cursym->value)
				continue;
			ASSERT(stubs[stub].symbol == NULL, "Stub at %06x in section %d has duplicate symbols: %s, %s", cursym->value, stubs_ndx,
			       stubs[stub].symbol->name, cursym->name);
			stubs[stub].symbol = cursym;
			break;
		}
		ASSERT(stub != num_stubs, "Global symbol %s in section %d not pointing to a valid stub", cursym->name, cursym->shndx);
	}
	return 1;
failure:
	return 0;
}

static int is_valid_relsection(vita_elf_t* ve, GElf_Shdr* rel) {
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

void vita_elf_free(vita_elf_t* ve) {
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

vita_elf_t* vita_elf_load(int fd) {
	vita_elf_t*  ve = NULL;
	GElf_Ehdr    ehdr;
	Elf_Scn*     scn;
	GElf_Shdr    shdr;
	size_t       shstrndx;
	char*        name;
	const char** debug_name;

	GElf_Phdr                phdr;
	size_t                   segment_count, segndx, loaded_segments;
	vita_elf_segment_info_t* curseg;

	ELF_ASSERT(elf_version(EV_CURRENT) != EV_NONE);
	ASSERT((ve = calloc(1, sizeof(vita_elf_t))) != NULL);
	ASSERT(varray_init(&ve->fstubs_va, sizeof(int), 8));
	ASSERT(varray_init(&ve->vstubs_va, sizeof(int), 4));
	for (ssize_t ret = PIPE_BUF; ret == PIPE_BUF; ve->size += (ret = read(fd, ve->file + ve->size, PIPE_BUF))) {
		ve->file = realloc(ve->file, ve->size + PIPE_BUF);
	}
	ELF_ASSERT(ve->elf = elf_memory(ve->file, ve->size));
	ASSERT(elf_kind(ve->elf) == ELF_K_ELF, "not an ELF file");
	ELF_ASSERT(gelf_getehdr(ve->elf, &ehdr));
	ASSERT(ehdr.e_machine == EM_ARM, "not an ARM binary");
	ASSERT(ehdr.e_ident[EI_CLASS] == ELFCLASS32 && ehdr.e_ident[EI_DATA] == ELFDATA2LSB, "not LE 32-bit");
	ELF_ASSERT(elf_getshdrstrndx(ve->elf, &shstrndx) == 0);

	scn = NULL;

	while ((scn = elf_nextscn(ve->elf, scn)) != NULL) {
		ELF_ASSERT(gelf_getshdr(scn, &shdr));
		ELF_ASSERT(name = elf_strptr(ve->elf, shstrndx, shdr.sh_name));
		if (shdr.sh_type == SHT_PROGBITS && strncmp(name, ".vitalink.fstubs", strlen(".vitalink.fstubs")) == 0) {
			int ndxscn = elf_ndxscn(scn);
			varray_push(&ve->fstubs_va, &ndxscn);
			ASSERT(load_stubs(scn, &ve->num_fstubs, &ve->fstubs, name));
		} else if (shdr.sh_type == SHT_PROGBITS && strncmp(name, ".vitalink.vstubs", strlen(".vitalink.vstubs")) == 0) {
			int ndxscn = elf_ndxscn(scn);
			varray_push(&ve->vstubs_va, &ndxscn);
			ASSERT(load_stubs(scn, &ve->num_vstubs, &ve->vstubs, name));
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			ASSERT(load_symbols(ve, scn));
		} else if (shdr.sh_type == SHT_REL) {
			if (!is_valid_relsection(ve, &shdr))
				continue;
			ASSERT(load_rel_table(ve, scn))
		} else if (shdr.sh_type == SHT_RELA) {
			if (!is_valid_relsection(ve, &shdr))
				continue;
			ASSERT(load_rela_table(ve, scn));
		}
	}

	if (!ve->fstubs_va.count)
		fprintf(stderr, "No stub found in .vitalink.");

	ASSERT(ve->symtab != NULL, "No symbol table in binary, perhaps stripped out");
	ASSERT(ve->rela_tables != NULL, "No relocation sections in binary; use -Wl,-q while compiling");
	if (ve->fstubs_va.count != 0) {
		ASSERT(lookup_stub_symbols(ve, ve->num_fstubs, ve->fstubs, &ve->fstubs_va, STT_FUNC));
	}
	if (ve->vstubs_va.count != 0) {
		ASSERT(lookup_stub_symbols(ve, ve->num_vstubs, ve->vstubs, &ve->vstubs_va, STT_OBJECT));
	}

	ELF_ASSERT(elf_getphdrnum(ve->elf, &segment_count) == 0);

	ve->segments = calloc(segment_count, sizeof(vita_elf_segment_info_t));
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
			ASSERT(curseg->vaddr_top != NULL, "Could not allocate address space for segment %d", (int)segndx);
			curseg->vaddr_bottom = curseg->vaddr_top + curseg->memsz;
		}
		loaded_segments++;
	}
	ve->num_segments = loaded_segments;

	return ve;

failure:
	if (ve != NULL)
		vita_elf_free(ve);
	return NULL;
}

static void free_rela_table(vita_elf_rela_table_t* rtable) {
	if (rtable == NULL)
		return;
	free(rtable->relas);
	free_rela_table(rtable->next);
	free(rtable);
}

typedef vita_imports_stub_t* (*find_stub_func_ptr)(vita_imports_module_t*, uint32_t);
static void lookup_stubs(vita_elf_stub_t* stubs, int num_stubs, find_stub_func_ptr find_stub, const char* stub_type_name) {
	for (vita_elf_stub_t* stub = stubs; stub < stubs + num_stubs; stub++) {
		stub->target = vita_imports_stub_new(stub->symbol ? stub->symbol->name : "(unreferenced stub)", 0);
	}
}

void vita_elf_lookup_imports(vita_elf_t* ve) {
	lookup_stubs(ve->fstubs, ve->num_fstubs, &vita_imports_find_function, "function");
	lookup_stubs(ve->vstubs, ve->num_vstubs, &vita_imports_find_variable, "variable");
}

const void* vita_elf_vaddr_to_host(const vita_elf_t* ve, Elf32_Addr vaddr) {
	for (vita_elf_segment_info_t* seg = ve->segments; seg < ve->segments + ve->num_segments; seg++) {
		if (vaddr >= seg->vaddr && vaddr < seg->vaddr + seg->memsz)
			return seg->vaddr_top + vaddr - seg->vaddr;
	}
	return NULL;
}
const void* vita_elf_segoffset_to_host(const vita_elf_t* ve, int segndx, uint32_t offset) {
	vita_elf_segment_info_t* seg = ve->segments + segndx;

	if (offset < seg->memsz)
		return seg->vaddr_top + offset;

	return NULL;
}

Elf32_Addr vita_elf_host_to_vaddr(const vita_elf_t* ve, const void* host_addr) {
	if (!host_addr)
		return 0;

	for (vita_elf_segment_info_t* seg = ve->segments; seg < ve->segments + ve->num_segments; seg++) {
		if (host_addr >= seg->vaddr_top && host_addr < seg->vaddr_bottom)
			return seg->vaddr + (uint32_t)(host_addr - seg->vaddr_top);
	}

	return 0;
}

int vita_elf_host_to_segndx(const vita_elf_t* ve, const void* host_addr) {
	vita_elf_segment_info_t* seg;
	int                      i;

	for (i = 0, seg = ve->segments; i < ve->num_segments; i++, seg++) {
		if (host_addr >= seg->vaddr_top && host_addr < seg->vaddr_bottom)
			return i;
	}

	return -1;
}

int32_t vita_elf_host_to_segoffset(const vita_elf_t* ve, const void* host_addr, int segndx) {
	vita_elf_segment_info_t* seg = ve->segments + segndx;

	if (host_addr == NULL)
		return 0;

	if (host_addr >= seg->vaddr_top && host_addr < seg->vaddr_bottom)
		return (uint32_t)(host_addr - seg->vaddr_top);

	return -1;
}

int vita_elf_vaddr_to_segndx(const vita_elf_t* ve, Elf32_Addr vaddr) {
	vita_elf_segment_info_t* seg;
	int                      i;

	for (i = 0, seg = ve->segments; i < ve->num_segments; i++, seg++) {
		/* Segments of type EXIDX will duplicate '.ARM.extab .ARM.exidx' sections already present in the data
		 * segment Since these won't be loaded, we should prefer the actual data segment */
		if (seg->type == SHT_ARM_EXIDX)
			continue;
		if (vaddr >= seg->vaddr && vaddr < seg->vaddr + seg->memsz)
			return i;
	}

	return -1;
}

/* vita_elf_vaddr_to_segoffset won't check the validity of the address, it may have been fuzzy-matched */
uint32_t vita_elf_vaddr_to_segoffset(const vita_elf_t* ve, Elf32_Addr vaddr, int segndx) { return vaddr ? vaddr - ve->segments[segndx].vaddr : 0; }

#endif
