#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <gelf.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <unistd.h>

#define ASSERT(cond, fmt...) \
	if (!(cond))         \
		return fprintf(stderr, "Failure:" #cond "\n" fmt), -1;
#define ELF_ASSERT(cond) ASSERT((cond) != 0, "[%i] %s\n", elf_errno(), elf_errmsg(elf_errno()))

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

static void free_rela_table(vita_elf_rela_table_t* rtable);

static int load_stubs(Elf_Scn* scn, int* num_stubs, vita_elf_stub_t** stubs, char* name) {
	GElf_Shdr shdr;
	gelf_getshdr(scn, &shdr);

	int old_num = *num_stubs;
	*num_stubs  = old_num + shdr.sh_size / 16;
	*stubs      = realloc(*stubs, *num_stubs * sizeof(vita_elf_stub_t));
	memset(&(*stubs)[old_num], 0, sizeof(vita_elf_stub_t) * shdr.sh_size / 16);

	name = strrchr(name, '.') + 1;

	vita_elf_stub_t* curstub = *stubs;
	curstub                  = &curstub[*num_stubs - (shdr.sh_size / 16)];

	Elf_Data* data = NULL;
	for (int total = 0; total < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL; total += data->d_size) {
		uint32_t* stub_data = (uint32_t*)data->d_buf;
		for (int chunk_offset = 0; chunk_offset < data->d_size; stub_data += 4, chunk_offset += 16) {
			curstub->addr          = shdr.sh_addr + data->d_off + chunk_offset;
			curstub->module        = vita_imports_module_new(name, false, 0, 0, 0);
			curstub->module->flags = le32toh(stub_data[0]);
			curstub->module_nid    = le32toh(stub_data[1]);
			curstub->target_nid    = le32toh(stub_data[2]);
			curstub++;
		}
	}

	return 1;
}

static int load_symbols(vita_elf_t* ve, Elf_Scn* scn) {
	if (elf_ndxscn(scn) == ve->symtab_ndx)
		return 0; /* Already loaded */

	ASSERT(ve->symtab == NULL, "ELF file appears to have multiple symbol tables!");

	GElf_Shdr shdr;
	gelf_getshdr(scn, &shdr);

	ve->num_symbols = shdr.sh_size / shdr.sh_entsize;
	ve->symtab      = calloc(ve->num_symbols, sizeof(vita_elf_symbol_t));
	ve->symtab_ndx  = (int)elf_ndxscn(scn);

	Elf_Data* data = NULL;
	for (int total = 0; total < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL; total += data->d_size) {
		Elf64_Xword data_beginsym = data->d_off / shdr.sh_entsize;
		for (int symndx = 0; symndx < data->d_size / shdr.sh_entsize; symndx++) {
			GElf_Sym sym;
			ELF_ASSERT(gelf_getsym(data, symndx, &sym) == &sym);
			vita_elf_symbol_t* cursym = ve->symtab + symndx + data_beginsym;
			cursym->name              = elf_strptr(ve->elf, shdr.sh_link, sym.st_name);
			cursym->value             = sym.st_value;
			cursym->type              = GELF_ST_TYPE(sym.st_info);
			cursym->binding           = GELF_ST_BIND(sym.st_info);
			cursym->shndx             = sym.st_shndx;
		}
	}

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

static int get_rel_handling(int type) {
	switch (type) {
	case R_ARM_NONE:
	case R_ARM_V4BX:
		return 0; //ignore
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
		return 1;
	}
	return -1;
}

static int load_rel_table(vita_elf_t* ve, Elf_Scn* scn, vita_elf_rela_table_t* rtable) {
	GElf_Shdr shdr, text_shdr;
	gelf_getshdr(scn, &shdr);

	ASSERT(!load_symbols(ve, elf_getscn(ve->elf, shdr.sh_link)));

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
		ASSERT(handling >= 0, "Invalid relocation type %d!", currela->type);

		if (!handling)
			continue;

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

	return 0;
}

static int load_rela_table(vita_elf_t* ve, Elf_Scn* scn) {
	fprintf(stderr, "RELA sections currently unsupported");
	return -1;
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
	for (int symndx = 0; symndx < ve->num_symbols; symndx++) {
		vita_elf_symbol_t* cursym = ve->symtab + symndx;
		if (cursym->binding != STB_GLOBAL)
			continue;
		if (cursym->type != STT_FUNC && cursym->type != STT_OBJECT)
			continue;
		int stubs_ndx = -1;
		for (int i = 0; i < stubs_va->count; i++) {
			int* cur_ndx = VARRAY_ELEMENT(stubs_va, i);
			if (cursym->shndx == *cur_ndx) {
				stubs_ndx = cursym->shndx;
				break;
			}
		}
		if (stubs_ndx == -1)
			continue;
		ASSERT(cursym->type == sym_type, "Global symbol %s in section %d expected to have type %s; instead has type %s", cursym->name, stubs_ndx,
		       elf_decode_st_type(sym_type), elf_decode_st_type(cursym->type));
		int stub;
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
			return 0;
		}
	}
	return -1;
}
/*
void vita_elf_free(vita_elf_t* ve) {
	int i;

	for (i = 0; i < ve->num_segments; i++) {
		if (ve->segments[i].vaddr_top != NULL)
			free((void*)ve->segments[i].vaddr_top);
	}

	// free() is safe to call on NULL
	free(ve->fstubs);
	free(ve->vstubs);
	free(ve->symtab);
	if (ve->elf != NULL)
		elf_end(ve->elf);
	if (ve->file != NULL)
		fclose(ve->file);
	free(ve);
}*/

int vita_elf_load(int fd, vita_elf_t* ve) {
	GElf_Ehdr ehdr;
	size_t    shstrndx;
	char*     name;

	ELF_ASSERT(elf_version(EV_CURRENT) != EV_NONE);
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

	for (Elf_Scn* scn = NULL; (scn = elf_nextscn(ve->elf, scn)) != NULL;) {
		GElf_Shdr shdr;
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
			ASSERT(!load_symbols(ve, scn));
		} else if (shdr.sh_type == SHT_REL) {
			if (is_valid_relsection(ve, &shdr) < 0)
				continue;
			vita_elf_rela_table_t* rtable = calloc(1, sizeof(vita_elf_rela_table_t));
			ASSERT(rtable != NULL);
			ASSERT(!load_rel_table(ve, scn, rtable));
		} else if (shdr.sh_type == SHT_RELA) {
			if (is_valid_relsection(ve, &shdr) < 0)
				continue;
			ASSERT(!load_rela_table(ve, scn));
		}
	}

	if (!ve->fstubs_va.count)
		fprintf(stderr, "No stub found in .vitalink.");

	ASSERT(ve->symtab != NULL, "No symbol table in binary, perhaps stripped out");
	ASSERT(ve->rela_tables != NULL, "No relocation sections in binary; use -Wl,-q while compiling");
	if (ve->fstubs_va.count != 0) {
		ASSERT(!lookup_stub_symbols(ve, ve->num_fstubs, ve->fstubs, &ve->fstubs_va, STT_FUNC));
	}
	if (ve->vstubs_va.count != 0) {
		ASSERT(!lookup_stub_symbols(ve, ve->num_vstubs, ve->vstubs, &ve->vstubs_va, STT_OBJECT));
	}

	size_t segment_count;
	ELF_ASSERT(elf_getphdrnum(ve->elf, &segment_count) == 0);

	ve->segments = calloc(segment_count, sizeof(vita_elf_segment_info_t));
	ASSERT(ve->segments != NULL);
	size_t loaded_segments = 0;

	for (size_t segndx = 0; segndx < segment_count; segndx++) {
		GElf_Phdr phdr;
		ELF_ASSERT(gelf_getphdr(ve->elf, segndx, &phdr));

		if (phdr.p_type != PT_LOAD) {
			continue; // skip non-loadable segments
		}
		vita_elf_segment_info_t* curseg;
		curseg        = ve->segments + loaded_segments;
		curseg->type  = phdr.p_type;
		curseg->vaddr = phdr.p_vaddr;
		curseg->memsz = phdr.p_memsz;

		if (curseg->memsz) {
			curseg->vaddr_top = malloc(curseg->memsz);
			ASSERT(curseg->vaddr_top != NULL, "Could not allocate address space for segment %zi", segndx);
			curseg->vaddr_bottom = curseg->vaddr_top + curseg->memsz;
		}
		loaded_segments++;
	}
	ve->num_segments = loaded_segments;

	return 0;
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
	return (offset < seg->memsz) ? seg->vaddr_top + offset : NULL;
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
	int i = 0;
	for (vita_elf_segment_info_t* seg = ve->segments; i < ve->num_segments; i++, seg++) {
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
	int i = 0;
	for (vita_elf_segment_info_t* seg = ve->segments; i < ve->num_segments; i++, seg++) {
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

const uint32_t sce_elf_stub_func[4] = {0xe3e00000, /* mvn r0, #0 */
                                       0xe12fff1e, /* bx lr */
                                       0xe1a00000, /* mov r0, r0 */
                                       0};
const uint32_t sce_elf_stub_var[4]  = {0, 0, 0, 0};

#define ALIGN_4(size) (((size) + 3) & ~0x3)

typedef struct {
	uint32_t               nid;
	vita_imports_module_t* module;

	union {
		vita_elf_stub_t* functions;
		varray           functions_va;
	};

	union {
		vita_elf_stub_t* variables;
		varray           variables_va;
	};
} import_module;

static int _stub_sort(const void* el1, const void* el2) {
	const vita_elf_stub_t *stub1 = el1, *stub2 = el2;
	if (stub2->target_nid > stub1->target_nid)
		return 1;
	else if (stub2->target_nid < stub1->target_nid)
		return -1;
	return 0;
}
static int _stub_nid_search(const void* key, const void* element) {
	const uint32_t*        nid  = key;
	const vita_elf_stub_t* stub = element;
	if (stub->target_nid > *nid)
		return 1;
	else if (stub->target_nid < *nid)
		return -1;
	return 0;
}

static void* _module_init(void* element) {
	import_module* module = element;
	if (!varray_init(&module->functions_va, sizeof(vita_elf_stub_t), 8))
		return NULL;
	if (!varray_init(&module->variables_va, sizeof(vita_elf_stub_t), 4))
		return NULL;

	module->functions_va.sort_compar   = _stub_sort;
	module->functions_va.search_compar = _stub_nid_search;
	module->variables_va.sort_compar   = _stub_sort;
	module->variables_va.search_compar = _stub_nid_search;

	return module;
}
static void _module_destroy(void* element) {
	import_module* module = element;
	varray_destroy(&module->functions_va);
	varray_destroy(&module->variables_va);
}

static int _module_sort(const void* el1, const void* el2) {
	const import_module *mod1 = el1, *mod2 = el2;
	if (mod2->nid > mod1->nid)
		return 1;
	else if (mod2->nid < mod1->nid)
		return -1;
	return 0;
}

static int _module_search(const void* key, const void* element) {
	const uint32_t*      nid    = key;
	const import_module* module = element;
	if (module->nid > *nid)
		return 1;
	else if (module->nid < *nid)
		return -1;
	return 0;
}

static bool get_symbol(const char* symbol, vita_elf_t* ve, uint8_t type, Elf32_Addr* vaddr) {
	for (int i = 0; i < ve->num_symbols; ++i) {
		if (ve->symtab[i].type != type)
			continue;
		if (strcmp(ve->symtab[i].name, symbol))
			continue;
		*vaddr = ve->symtab[i].value;
		return true;
	}
	return false;
}

typedef union {
	import_module* modules;
	varray         va;
} import_module_list;

static int set_module_export(vita_elf_t* ve, sce_module_exports_t* export, vita_library_export* lib) {
	export->size           = sizeof(sce_module_exports_raw);
	export->version        = 1;
	export->flags          = lib->syscall ? 0x4001 : 0x0001;
	export->num_syms_funcs = lib->function_n;
	export->num_syms_vars  = lib->variable_n;
	export->module_name    = strdup(lib->name);
	export->module_nid     = lib->nid;

	int total_exports   = export->num_syms_funcs + export->num_syms_vars;
	export->nid_table   = calloc(total_exports, sizeof(uint32_t));
	export->entry_table = calloc(total_exports, sizeof(void*));

	int cur_ent = 0;
	for (vita_export_symbol* sym = *lib->functions; sym < *lib->functions + export->num_syms_funcs; ++sym) {
		Elf32_Addr vaddr = 0;
		ASSERT(get_symbol(sym->name, ve, STT_FUNC, &vaddr), "Could not find function symbol '%s' for export '%s'", sym->name, lib->name);
		export->nid_table[cur_ent]   = sym->nid;
		export->entry_table[cur_ent] = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_ent;
	}

	for (vita_export_symbol* sym = *lib->variables; sym < *lib->variables + export->num_syms_vars; ++sym) {
		Elf32_Addr vaddr = 0;
		ASSERT(get_symbol(sym->name, ve, STT_OBJECT, &vaddr), "Could not find variable symbol '%s' for export '%s'", sym->name, lib->name);
		export->nid_table[cur_ent]   = sym->nid;
		export->entry_table[cur_ent] = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_ent;
	}

	return 0;
}

static int set_main_module_export(vita_elf_t* ve, sce_module_exports_t* export, sce_module_info_t* module_info, vita_export_t* export_spec) {
	export->size           = sizeof(sce_module_exports_raw);
	export->version        = 0;
	export->flags          = 0x8000;
	export->num_syms_funcs = 1 + !!export_spec->stop + !!export_spec->exit;
	export->num_syms_vars  = 2;

	int total_exports   = export->num_syms_funcs + export->num_syms_vars;
	export->nid_table   = calloc(total_exports, sizeof(uint32_t));
	export->entry_table = calloc(total_exports, sizeof(void*));

	int cur_nid = 0;

	if (export_spec->start) {
		Elf32_Addr vaddr = 0;
		ASSERT(get_symbol(export_spec->start, ve, STT_FUNC, &vaddr), "Could not find symbol '%s' for main export 'start'", export_spec->start);
		module_info->module_start = vita_elf_vaddr_to_host(ve, vaddr);
	} else
		module_info->module_start = vita_elf_vaddr_to_host(ve, elf32_getehdr(ve->elf)->e_entry);

	export->nid_table[cur_nid]   = NID_MODULE_START;
	export->entry_table[cur_nid] = module_info->module_start;
	++cur_nid;

	if (export_spec->stop) {
		Elf32_Addr vaddr = 0;

		ASSERT(get_symbol(export_spec->stop, ve, STT_FUNC, &vaddr), "Could not find symbol '%s' for main export 'stop'", export_spec->stop);

		export->nid_table[cur_nid]   = NID_MODULE_STOP;
		export->entry_table[cur_nid] = module_info->module_stop = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_nid;
	}

	if (export_spec->exit) {
		Elf32_Addr vaddr = 0;

		ASSERT(get_symbol(export_spec->exit, ve, STT_FUNC, &vaddr), "Could not find symbol '%s' for main export 'exit'", export_spec->exit);

		export->nid_table[cur_nid]   = NID_MODULE_EXIT;
		export->entry_table[cur_nid] = vita_elf_vaddr_to_host(ve, vaddr);
		++cur_nid;
	}

	export->nid_table[cur_nid]   = NID_MODULE_INFO;
	export->entry_table[cur_nid] = module_info;
	++cur_nid;

	export->nid_table[cur_nid]   = NID_PROCESS_PARAM;
	export->entry_table[cur_nid] = &module_info->process_param_size;
	++cur_nid;

	return 0;
}

static void set_module_import(vita_elf_t* ve, sce_module_imports_t* imp, const import_module* module) {
	imp->size             = sizeof(sce_module_imports_raw);
	imp->version          = 1;
	imp->num_syms_funcs   = module->functions_va.count;
	imp->num_syms_vars    = module->variables_va.count;
	imp->module_nid       = module->nid;
	imp->flags            = module->module->flags;
	imp->module_name      = module->module ? module->module->name : imp->module_name;
	imp->func_nid_table   = calloc(module->functions_va.count, sizeof(uint32_t));
	imp->func_entry_table = calloc(module->functions_va.count, sizeof(void*));
	for (int i = 0; i < module->functions_va.count; i++) {
		imp->func_nid_table[i]   = module->functions[i].target_nid;
		imp->func_entry_table[i] = vita_elf_vaddr_to_host(ve, module->functions[i].addr);
	}
	imp->var_nid_table   = calloc(module->variables_va.count, sizeof(uint32_t));
	imp->var_entry_table = calloc(module->variables_va.count, sizeof(void*));
	for (int i = 0; i < module->variables_va.count; i++) {
		imp->var_nid_table[i]   = module->variables[i].target_nid;
		imp->var_entry_table[i] = vita_elf_vaddr_to_host(ve, module->variables[i].addr);
	}
}

void sce_elf_module_info_free(sce_module_info_t* module_info) {
	if (module_info == NULL)
		return;

	for (sce_module_exports_t* export = module_info->export_top; export < module_info->export_end; export ++) {
		free(export->nid_table);
		free(export->entry_table);
	}
	free(module_info->export_top);

	for (sce_module_imports_t* imp = module_info->import_top; imp < module_info->import_end; imp++) {
		free(imp->func_nid_table);
		free(imp->func_entry_table);
		free(imp->var_nid_table);
		free(imp->var_entry_table);
		free(imp->unk_nid_table);
		free(imp->unk_entry_table);
	}

	free(module_info->import_top);
}

int sce_elf_module_info_create(vita_elf_t* ve, vita_export_t* exports, sce_module_info_t* module_info) {
	module_info->type    = 6;
	module_info->version = (exports->ver_major << 8) | exports->ver_minor;

	strncpy(module_info->name, exports->name, sizeof(module_info->name) - 1);

	// allocate memory for all libraries + main
	module_info->export_top = calloc(exports->module_n + 1, sizeof(sce_module_exports_t));
	ASSERT(module_info->export_top != NULL);
	module_info->export_end = module_info->export_top + exports->module_n + 1;

	ASSERT(set_main_module_export(ve, module_info->export_top, module_info, exports) >= 0);

	// populate rest of exports
	for (int i = 0; i < exports->module_n; ++i) {
		vita_library_export*  lib = exports->modules[i];
		sce_module_exports_t* exp = /*(sce_module_exports_t*)*/ (module_info->export_top + i + 1);

		// TODO: improve cleanup
		ASSERT(set_module_export(ve, exp, lib) >= 0);
	}

	import_module_list modlist = {0};
	ASSERT(varray_init(&modlist.va, sizeof(import_module), 8));
	modlist.va.init_func     = _module_init;
	modlist.va.destroy_func  = _module_destroy;
	modlist.va.sort_compar   = _module_sort;
	modlist.va.search_compar = _module_search;

	for (int i = 0; i < ve->num_fstubs; i++) {
		vita_elf_stub_t* curstub   = ve->fstubs + i;
		import_module*   curmodule = varray_sorted_search_or_insert(&modlist.va, &curstub->module_nid, NULL);
		ASSERT(curmodule);
		curmodule->nid = curstub->module_nid;
		if (curstub->module)
			curmodule->module = curstub->module;

		varray_sorted_insert_ex(&curmodule->functions_va, curstub, 0);
	}

	for (int i = 0; i < ve->num_vstubs; i++) {
		vita_elf_stub_t* curstub   = ve->vstubs + i;
		import_module*   curmodule = varray_sorted_search_or_insert(&modlist.va, &curstub->module_nid, NULL);
		ASSERT(curmodule);
		curmodule->nid = curstub->module_nid;
		if (curstub->module)
			curmodule->module = curstub->module;

		varray_sorted_insert_ex(&curmodule->variables_va, curstub, 0);
	}

	module_info->import_top = calloc(modlist.va.count, sizeof(sce_module_imports_t));
	ASSERT(module_info->import_top != NULL);
	module_info->import_end = module_info->import_top + modlist.va.count;

	for (int i = 0; i < modlist.va.count; i++) {
		set_module_import(ve, module_info->import_top + i, modlist.modules + i);
	}

	return 0;
	//TODO: failure:
	//	varray_destroy(&modlist.va);
	//	sce_elf_module_info_free(module_info);
}

size_t sce_elf_module_info_get_size(sce_module_info_t* module_info, sce_section_sizes_t* sizes) {
	sce_module_exports_t* export;
	sce_module_imports_t* import;

	memset(sizes, 0, sizeof(*sizes));

	sizes->sceModuleInfo_rodata += sizeof(sce_module_info_raw);
	for (export = module_info->export_top; export < module_info->export_end; export ++) {
		sizes->sceLib_ent += sizeof(sce_module_exports_raw);
		if (export->module_name != NULL) {
			sizes->sceExport_rodata += ALIGN_4(strlen(export->module_name) + 1);
		}
		sizes->sceExport_rodata += (export->num_syms_funcs + export->num_syms_vars + export->num_syms_unk) * 8;
	}

	for (import = module_info->import_top; import < module_info->import_end; import++) {
		(sizes->sceLib_stubs += sizeof(sce_module_imports_raw));
		if (import->module_name != NULL) {
			(sizes->sceImport_rodata += ALIGN_4(strlen(import->module_name) + 1));
		}
		sizes->sceFNID_rodata += import->num_syms_funcs * 4;
		sizes->sceFStub_rodata += import->num_syms_funcs * 4;
		sizes->sceVNID_rodata += import->num_syms_vars * 4;
		sizes->sceVStub_rodata += import->num_syms_vars * 4;
		sizes->sceImport_rodata += import->num_syms_unk * 8;
	}
	size_t total_size = 0;
	for (size_t i = 0; i < sizeof(sce_section_sizes_t) / sizeof(uint32_t); i++) {
		total_size += ((uint32_t*)sizes)[i];
	}
	return total_size;
}

#define INCR(section, size)                                                                                \
	do {                                                                                               \
		cur_sizes.section += (size);                                                               \
		ASSERT(cur_sizes.section <= sizes->section, "Attempted to overrun section %s!", #section); \
		section_addrs.section += (size);                                                           \
	} while (0)
#define ADDR(section) (data + section_addrs.section)
#define INTADDR(section) (*((uint32_t*)ADDR(section)))
#define VADDR(section) (section_addrs.section + segment_base + start_offset)
#define OFFSET(section) (section_addrs.section + start_offset)
#define CONVERT(variable, member, conversion) variable##_raw->member = conversion(variable->member)
#define CONVERT16(variable, member) CONVERT(variable, member, htole16)
#define CONVERT32(variable, member) CONVERT(variable, member, htole32)
#define CONVERTOFFSET(variable, member) variable##_raw->member = htole32(vita_elf_host_to_segoffset(ve, variable->member, segndx))
#define SETLOCALPTR(variable, section)              \
	do {                                        \
		variable = htole32(VADDR(section)); \
		ADDRELA(&variable);                 \
	} while (0)
#define ADDRELA(localaddr)                                                                                 \
	do {                                                                                               \
		uint32_t addend = le32toh(*((uint32_t*)localaddr));                                        \
		if (addend) {                                                                              \
			vita_elf_rela_t* rela = varray_push(&relas, NULL);                                 \
			rela->type            = R_ARM_ABS32;                                               \
			rela->offset          = ((void*)(localaddr)) - data + segment_base + start_offset; \
			rela->addend          = addend;                                                    \
		}                                                                                          \
	} while (0)

int sce_elf_module_info_encode(sce_module_info_t* module_info, vita_elf_t* ve, sce_section_sizes_t* sizes, vita_elf_rela_table_t* rtable, void* data) {
	varray relas;
	ASSERT(varray_init(&relas, sizeof(vita_elf_rela_t), 16));

	int                 total_size    = 0;
	sce_section_sizes_t section_addrs = {0};
	sce_section_sizes_t cur_sizes     = {0};
	for (int i = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		((Elf32_Word*)&section_addrs)[i] = total_size;
		total_size += ((Elf32_Word*)sizes)[i];
	}

	int segndx = vita_elf_host_to_segndx(ve, module_info->module_start);

	Elf32_Addr segment_base = ve->segments[segndx].vaddr;
	Elf32_Word start_offset = ve->segments[segndx].memsz;
	start_offset            = (start_offset + 0xF) & ~0xF; // align to 16 bytes

	for (int i = 0; i < ve->num_segments; i++) {
		if (i == segndx)
			continue;
		int pos = ve->segments[i].vaddr - segment_base - start_offset;
		ASSERT((pos < 0) || (pos >= total_size), "Cannot allocate %d B for SCEdata at end of seg[%d]: seg[%d] overlaps", total_size, segndx, i);
	}

	ASSERT(data != NULL);

	sce_module_info_raw* module_info_raw = /*(sce_module_info_raw*)*/ ADDR(sceModuleInfo_rodata);
	INCR(sceModuleInfo_rodata, sizeof(sce_module_info_raw));
	CONVERT16(module_info, attributes);
	CONVERT16(module_info, version);
	memcpy(module_info_raw->name, module_info->name, 27);
	module_info_raw->type       = module_info->type;
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

	for (sce_module_exports_t* export = module_info->export_top; export < module_info->export_end; export ++) {
		int       num_syms;
		uint32_t *raw_nids, *raw_entries;

		sce_module_exports_raw* export_raw = /*(sce_module_exports_raw*)*/ ADDR(sceLib_ent);
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
			void* dst = ADDR(sceExport_rodata);
			INCR(sceExport_rodata, ALIGN_4(strlen(export->module_name) + 1));
			strcpy(dst, export->module_name);
		}
		num_syms = export->num_syms_funcs + export->num_syms_vars + export->num_syms_unk;
		SETLOCALPTR(export_raw->nid_table, sceExport_rodata);
		raw_nids = (uint32_t*)ADDR(sceExport_rodata);
		INCR(sceExport_rodata, num_syms * 4);
		SETLOCALPTR(export_raw->entry_table, sceExport_rodata);
		raw_entries = (uint32_t*)ADDR(sceExport_rodata);
		INCR(sceExport_rodata, num_syms * 4);
		for (int i = 0; i < num_syms; i++) {
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

	for (sce_module_imports_t* import = module_info->import_top; import < module_info->import_end; import++) {
		sce_module_imports_raw* import_raw = /*(sce_module_imports_raw*)*/ ADDR(sceLib_stubs);
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
			void* dst = ADDR(sceImport_rodata);
			INCR(sceImport_rodata, ALIGN_4(strlen(import->module_name) + 1));
			strcpy(dst, import->module_name);
		}
		if (import->num_syms_funcs) {
			SETLOCALPTR(import_raw->func_nid_table, sceFNID_rodata);
			SETLOCALPTR(import_raw->func_entry_table, sceFStub_rodata);
			for (int i = 0; i < import->num_syms_funcs; i++) {
				INTADDR(sceFNID_rodata)  = htole32(import->func_nid_table[i]);
				INTADDR(sceFStub_rodata) = htole32(vita_elf_host_to_vaddr(ve, import->func_entry_table[i]));
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
				INTADDR(sceVStub_rodata) = htole32(vita_elf_host_to_vaddr(ve, import->var_entry_table[i]));
				ADDRELA(ADDR(sceVStub_rodata));
				INCR(sceVNID_rodata, 4);
				INCR(sceVStub_rodata, 4);
			}
		}
		if (import->num_syms_unk) {
			SETLOCALPTR(import_raw->unk_nid_table, sceImport_rodata);
			for (int i = 0; i < import->num_syms_unk; i++) {
				INTADDR(sceImport_rodata) = htole32(import->var_nid_table[i]);
				INCR(sceImport_rodata, 4);
			}
			SETLOCALPTR(import_raw->unk_entry_table, sceImport_rodata);
			for (int i = 0; i < import->num_syms_unk; i++) {
				INTADDR(sceImport_rodata) = htole32(vita_elf_host_to_vaddr(ve, import->var_entry_table[i]));
				ADDRELA(ADDR(sceImport_rodata));
				INCR(sceImport_rodata, 4);
			}
		}
	}

	for (int i = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		ASSERT((((Elf32_Word*)&cur_sizes)[i] == ((Elf32_Word*)sizes)[i]), "remaining space in section %d!", i);
	}

	rtable->num_relas = relas.count;
	rtable->relas     = varray_extract_array(&relas);

	return 0;
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
	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	if (ehdr.e_shoff >= start_offset) {
		ehdr.e_shoff += shift_amount;
		ELF_ASSERT(gelf_update_ehdr(e, &ehdr));
	}

	int bottom_section_offset = 0;
	for (Elf_Scn* scn = NULL; (scn = elf_nextscn(e, scn)) != NULL;) {
		GElf_Shdr shdr;
		ELF_ASSERT(gelf_getshdr(scn, &shdr));
		if (shdr.sh_offset >= start_offset) {
			shdr.sh_offset += shift_amount;
			ELF_ASSERT(gelf_update_shdr(scn, &shdr));
		}
		GElf_Xword sh_size = (shdr.sh_type == SHT_NOBITS) ? 0 : shdr.sh_size;
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
	size_t segment_count = 0;
	ELF_ASSERT((elf_getphdrnum(e, &segment_count), segment_count > 0));

	for (size_t segndx = 0; segndx < segment_count; segndx++) {
		GElf_Phdr phdr;
		ELF_ASSERT(gelf_getphdr(e, segndx, &phdr));
		if (phdr.p_offset >= start_offset) {
			phdr.p_offset += shift_amount;
			ELF_ASSERT(gelf_update_phdr(e, segndx, &phdr));
		}
	}

	return 0;
}

int elf_utils_new_scn_with_name(Elf* e, const char* scn_name, Elf_Scn** scn) {
	GElf_Shdr shdr;
	size_t    shstrndx;
	Elf_Data* shstrdata;
	void*     ptr;

	ELF_ASSERT(!elf_getshdrstrndx(e, &shstrndx));

	ELF_ASSERT(*scn = elf_getscn(e, shstrndx));
	char* str = elf_strptr(e, shstrndx, 0);
	ELF_ASSERT(shstrdata = elf_getdata(*scn, NULL));

	size_t namelen = strlen(scn_name) + 1;
	ELF_ASSERT(gelf_getshdr(*scn, &shdr));
	ASSERT(!elf_utils_shift_contents(e, shdr.sh_offset + shdr.sh_size, namelen));
	ASSERT(ptr = realloc(shstrdata->d_buf, shstrdata->d_size + namelen));
	size_t index = shstrdata->d_size;
	strcpy(ptr + index, scn_name);
	shstrdata->d_buf = ptr;
	shstrdata->d_size += namelen;
	shdr.sh_size += namelen;
	ELF_ASSERT(gelf_update_shdr(*scn, &shdr));

	ELF_ASSERT(*scn = elf_newscn(e));
	ELF_ASSERT(gelf_getshdr(*scn, &shdr));
	shdr.sh_name = index;
	ELF_ASSERT(gelf_update_shdr(*scn, &shdr));

	return 0;
}

int sce_elf_write_module_info(Elf* dest, vita_elf_t* ve, sce_section_sizes_t* sizes, void* module_info) {
	/* Corresponds to the order in sce_section_sizes_t */
	static const char*  section_names[] = {".sceModuleInfo.rodata", ".sceLib.ent",      ".sceExport.rodata", ".sceLib.stubs",   ".sceImport.rodata",
                                              ".sceFNID.rodata",       ".sceFStub.rodata", ".sceVNID.rodata",   ".sceVStub.rodata"};
	sce_section_sizes_t section_addrs   = {0};
	int                 total_size      = 0;
	for (size_t i = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		((Elf32_Word*)&section_addrs)[i] = total_size;
		total_size += ((Elf32_Word*)sizes)[i];
	}

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(dest, &ehdr));

	int segndx;
	for (segndx = 0; segndx < ve->num_segments; segndx++) {
		if (ehdr.e_entry >= ve->segments[segndx].vaddr && ehdr.e_entry < ve->segments[segndx].vaddr + ve->segments[segndx].memsz) {
			break;
		}
	}
	ASSERT(segndx < ve->num_segments);

	GElf_Phdr phdr;
	ELF_ASSERT(gelf_getphdr(dest, segndx, &phdr));

	Elf32_Addr segment_base    = ve->segments[segndx].vaddr;
	Elf32_Word start_segoffset = ve->segments[segndx].memsz;
	start_segoffset            = (start_segoffset + 0xF) & ~0xF;  // align to 16 bytes, same with `sce_elf_module_info_encode`
	total_size += (start_segoffset - ve->segments[segndx].memsz); // add the padding size

	Elf32_Addr start_vaddr   = segment_base + start_segoffset;
	Elf32_Word start_foffset = phdr.p_offset + start_segoffset;

	ASSERT(!elf_utils_shift_contents(dest, start_foffset, total_size), "Unable to relocate ELF sections\n");

	/* Extend in our copy of phdrs so that vita_elf_vaddr_to_segndx can match it */
	ve->segments[segndx].memsz += total_size;

	phdr.p_filesz += total_size;
	phdr.p_memsz += total_size;
	ELF_ASSERT(gelf_update_phdr(dest, segndx, &phdr));

	ELF_ASSERT(gelf_getehdr(dest, &ehdr));
	ehdr.e_entry = ((segndx & 0x3) << 30) | start_segoffset;
	ELF_ASSERT(gelf_update_ehdr(dest, &ehdr));

	for (size_t i = 0, cur_pos = 0; i < sizeof(sce_section_sizes_t) / sizeof(Elf32_Word); i++) {
		int scn_size = ((Elf32_Word*)sizes)[i];
		if (scn_size == 0)
			continue;

		Elf_Scn* scn;
		ASSERT(!elf_utils_new_scn_with_name(dest, section_names[i], &scn));
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
		data->d_buf     = module_info + cur_pos;
		data->d_type    = ELF_T_BYTE;
		data->d_version = EV_CURRENT;
		data->d_size    = scn_size;
		data->d_off     = 0;
		data->d_align   = 1;

		cur_pos += scn_size;
	}

	return 0;
}

static int sce_rel_short(SCE_Rel* rel, int symseg, int code, int datseg, int offset, int addend) {
	if (addend > 1 << 11)
		return 0;
	rel->r_short_entry.r_short     = 1;
	rel->r_short_entry.r_symseg    = symseg;
	rel->r_short_entry.r_code      = code;
	rel->r_short_entry.r_datseg    = datseg;
	rel->r_short_entry.r_offset_lo = offset & 0xFFF;
	rel->r_short_entry.r_offset_hi = offset >> 20;
	rel->r_short_entry.r_addend    = addend;
	return 1;
}

static int sce_rel_long(SCE_Rel* rel, int symseg, int code, int datseg, int offset, int addend) {
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

static int encode_sce_rel(SCE_Rel* rel) {
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
int sce_elf_discard_invalid_relocs(const vita_elf_t* ve, vita_elf_rela_table_t* rtable) {
	for (vita_elf_rela_table_t* curtable = rtable; curtable; curtable = curtable->next) {
		int datseg, i = 0;
		for (vita_elf_rela_t* vrela = curtable->relas; i < curtable->num_relas; i++, vrela++) {
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
	return 0;
}

int elf_utils_new_scn_with_data(Elf* e, const char* scn_name, void* buf, int len, Elf_Scn** scn) {
	ASSERT(!elf_utils_new_scn_with_name(e, scn_name, scn));

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(e, &ehdr));
	int offset = ehdr.e_shoff;
	ASSERT(!elf_utils_shift_contents(e, offset, len + 0x10));

	GElf_Shdr shdr;
	ELF_ASSERT(gelf_getshdr(*scn, &shdr));
	shdr.sh_offset    = (offset + 0x10) & ~0xF;
	shdr.sh_size      = len;
	shdr.sh_addralign = 1;
	ELF_ASSERT(gelf_update_shdr(*scn, &shdr));

	Elf_Data* data;
	ELF_ASSERT(data = elf_newdata(*scn));
	data->d_buf     = buf;
	data->d_type    = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	data->d_size    = len;
	data->d_off     = 0;
	data->d_align   = 1;

	return 0;
}

size_t sce_elf_count_rela_sections(vita_elf_rela_table_t* rtable) {
	size_t total_relas = 0;
	for (vita_elf_rela_table_t* curtable = rtable; curtable; curtable = curtable->next) {
		total_relas += curtable->num_relas;
	}
	return total_relas;
}
int sce_elf_write_rela_sections(Elf* dest, vita_elf_t* ve, vita_elf_rela_table_t* rtable, void* encoded_relas) {
	int (*sce_rel_func)(SCE_Rel*, int, int, int, int, int) = sce_rel_long; // sce_rel_short
	void* curpos;
encode_relas:
	curpos = encoded_relas;
	for (vita_elf_rela_table_t* curtable = rtable; curtable; curtable = curtable->next) {
		for (vita_elf_rela_t* vrela = curtable->relas; vrela < (curtable->relas + curtable->num_relas); vrela++) {
			if (vrela->type == R_ARM_NONE)
				continue;
			Elf32_Word datseg   = vita_elf_vaddr_to_segndx(ve, vrela->offset);
			Elf32_Word datoff   = vita_elf_vaddr_to_segoffset(ve, vrela->offset, datseg);
			Elf32_Addr symvaddr = vrela->symbol ? vrela->symbol->value + vrela->addend : vrela->addend;
			Elf32_Word symseg   = vita_elf_vaddr_to_segndx(ve, vrela->symbol ? vrela->symbol->value : vrela->addend);
			if (symseg == -1)
				continue;
			SCE_Rel    rel;
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
	Elf_Scn* scn;
	ASSERT(!elf_utils_new_scn_with_data(dest, ".sce.rel", encoded_relas, curpos - encoded_relas, &scn));
	encoded_relas = NULL;

	GElf_Shdr shdr;
	ELF_ASSERT(gelf_getshdr(scn, &shdr));
	shdr.sh_type      = SHT_SCE_RELA;
	shdr.sh_flags     = 0;
	shdr.sh_addralign = 4;
	ELF_ASSERT(gelf_update_shdr(scn, &shdr));

	size_t segment_count = 0;
	ELF_ASSERT((elf_getphdrnum(dest, &segment_count), segment_count > 0));
	GElf_Phdr* phdrs = calloc(segment_count + 1, sizeof(GElf_Phdr));
	ASSERT(phdrs);
	for (int i = 0; i < segment_count; i++) {
		ELF_ASSERT(gelf_getphdr(dest, i, phdrs + i));
	}
	ELF_ASSERT(gelf_newphdr(dest, segment_count + 1));
	ELF_ASSERT(gelf_getphdr(dest, segment_count, phdrs + segment_count));
	phdrs[segment_count].p_type   = PT_SCE_RELA;
	phdrs[segment_count].p_offset = shdr.sh_offset;
	phdrs[segment_count].p_filesz = shdr.sh_size;
	phdrs[segment_count].p_align  = 16;
	for (int i = 0; i < segment_count + 1; i++) {
		ELF_ASSERT(gelf_update_phdr(dest, i, phdrs + i));
	}

	return 0;
}

int sce_elf_rewrite_stub(Elf* dest, void* shstrtab, const varray* va, char* sec_name, char* sec_fmt, const uint32_t* stub) {
	for (int j = 0; j < va->count; j++) {
		int*      cur_ndx = VARRAY_ELEMENT(va, j);
		Elf_Scn*  scn;
		GElf_Shdr shdr;
		ELF_ASSERT(scn = elf_getscn(dest, *cur_ndx));
		ELF_ASSERT(gelf_getshdr(scn, &shdr));

		char* sh_name = shstrtab + shdr.sh_name;
		if (strstr(sh_name, sec_name) != sh_name)
			return fprintf(stderr, "Malformed %s section.", sec_name), 0;
		char* stub_name = strrchr(sh_name, '.');
		snprintf(sh_name, strlen(sh_name) + 1, sec_fmt, stub_name);

		for (Elf_Data* data = NULL; (data = elf_getdata(scn, data));) {
			for (uint32_t* stubdata = (uint32_t*)data->d_buf; (void*)stubdata < data->d_buf + data->d_size - 11; stubdata += 4) {
				stubdata[0] = htole32(stub[0]);
				stubdata[1] = htole32(stub[1]);
				stubdata[2] = htole32(stub[2]);
				stubdata[3] = htole32(stub[3]);
			}
		}
	}
	return 0;
}

int sce_elf_rewrite_stubs(Elf* dest, const vita_elf_t* ve) {
	size_t shstrndx;
	ELF_ASSERT(elf_getshdrstrndx(dest, &shstrndx) == 0);
	Elf_Scn* scn = elf_getscn(dest, shstrndx);
	ELF_ASSERT(scn);
	Elf_Data* data = elf_getdata(scn, NULL);
	ELF_ASSERT(data);

	sce_elf_rewrite_stub(dest, data->d_buf, &ve->fstubs_va, ".vitalink.fstubs.", ".text.fstubs%s", sce_elf_stub_func);
	sce_elf_rewrite_stub(dest, data->d_buf, &ve->vstubs_va, ".vitalink.vstubs.", ".data.vstubs%s", sce_elf_stub_var);

	return 0;
}
