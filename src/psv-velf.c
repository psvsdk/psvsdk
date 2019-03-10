/**
USAGE
	%s [-e export.yml] <a.elf >a.velf

EXAMPLES
	%s < a.out > main.velf
	%s -e main.yml < a.out > main.velf

Produce a SCE REL ELF and it export.yaml file from an static linked ELF.
- Read the.vitalink.fstubs+.vitalink.vstubs from ELF.
- Build a list of imports from each library required.
- Create the.sceModuleInfo.rodatasection by generating a module info for the input ELF.
- Create the export tables with the optional YAML configuration.
- Create the import tables with the list from stubs + db.yml.
- Convert all non-supported relocations to a supported type (optionally, for patched linker)
- Open a new ELF with type ET_SCE_EXEC or ET_SCE_REL_EXEC for writing.
- Build the output SCE ELF by copying over the first loadable program segment and then writing all the module info,
export, and import data to the end of the segment, extending the size of the segment. Make sure the offsets and pointers
in the SCE sections are updated to match its new location.
- Update p_paddr of the first segment to point to the module info (for ET_SCE_EXEC types) or e_entry to point to modinfo (for ET_SCE_RELEXEC types).
- Write import stubs over the temporary entries in.vitalink.fstubs and .vitalink.vstubs.
- Copy over the other program segments (if needed).
- Create a new program segment of type PT_SCE_RELA and create SCE relocation entries based on the ELF relocation entries
of the input ELF.
*/
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "varray.h"
#include "velf.h"
#include <libelf/libelf.h>
typedef struct {
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

#include "velf.c" // TODO: extract vita_elf_t function from it
#ifndef USAGE
#define USAGE "see man psv-velf"
#endif

int elf_scndup(Elf* e, size_t scndx) {
	Elf_Scn* scn = elf_getscn(e, scndx);
	ELF_ASSERT(scn);
	for (Elf_Data* data = NULL; (data = elf_getdata(scn, data));) {
		void* new_data = malloc(data->d_size);
		ASSERT(new_data);
		memcpy(new_data, data->d_buf, data->d_size);
		data->d_buf = new_data;
	}

	return 0;
}

/* Generate a dest elf with, same ehdr, dup sections (header+data), dup phdrs as src*/
int elf_dup(Elf* source, Elf* dest) {
	ELF_ASSERT(elf_flagelf(dest, ELF_C_SET, ELF_F_LAYOUT));

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(source, &ehdr));
	ELF_ASSERT(gelf_newehdr(dest, gelf_getclass(source)));
	ELF_ASSERT(gelf_update_ehdr(dest, &ehdr));

	for (Elf_Scn *dst_scn, *src_scn = NULL; (src_scn = elf_nextscn(source, src_scn));) {
		GElf_Shdr src_shdr;
		ELF_ASSERT(gelf_getshdr(src_scn, &src_shdr));
		ELF_ASSERT(dst_scn = elf_newscn(dest));
		ELF_ASSERT(gelf_update_shdr(dst_scn, &src_shdr));

		for (Elf_Data* src_data = NULL; (src_data = elf_getdata(src_scn, src_data));) {
			Elf_Data* dst_data = elf_newdata(dst_scn);
			ELF_ASSERT(dst_data);
			memcpy(dst_data, src_data, sizeof(Elf_Data));
		}
	}

	size_t segment_count;
	ELF_ASSERT(elf_getphdrnum(source, &segment_count) == 0);

	// count PT_LOAD segments
	size_t segment_ptload = 0;
	for (size_t segndx = 0; segndx < segment_count; segndx++) {
		GElf_Phdr phdr;
		ELF_ASSERT(gelf_getphdr(source, segndx, &phdr));
		segment_ptload += (phdr.p_type == PT_LOAD);
	}
	ASSERT(segment_ptload > 0);

	// copy PT_LOAD segments
	ELF_ASSERT(gelf_newphdr(dest, segment_ptload));
	segment_ptload = 0;
	for (size_t segndx = 0; segndx < segment_count; segndx++) {
		GElf_Phdr phdr;
		ELF_ASSERT(gelf_getphdr(source, segndx, &phdr));
		if (phdr.p_type == PT_LOAD) {
			ELF_ASSERT(gelf_update_phdr(dest, segment_ptload, &phdr));
			segment_ptload++;
		}
	}

	return 0;
}

int main(int argc, char* argv[]) {
	argc--;
	argv++;
	ASSERT(argc == 2, USAGE);
	vita_export_t exports = {.ver_major = 1, .ver_minor = 1, .nid = 0x00000000, .name = "/main.elf"};

	vita_elf_t *ve = calloc(1, sizeof(vita_elf_t)); // will be realoc-ed ?!
	ASSERT(ve != NULL);
	ASSERT(!vita_elf_load(open(argv[0], O_RDONLY), ve));
	vita_elf_lookup_imports(ve);
	sce_module_info_t module_info = {};
	sce_elf_module_info_create(ve, &exports, &module_info);
	sce_section_sizes_t   section_sizes;
	size_t                allSize = sce_elf_module_info_get_size(&module_info, &section_sizes);
	vita_elf_rela_table_t rtable  = {};

	void* encoded_modinfo = calloc(1, allSize);
	ASSERT(encoded_modinfo != NULL);
	ASSERT(!sce_elf_module_info_encode(&module_info, ve, &section_sizes, &rtable, encoded_modinfo));

	int  outfd = open(argv[1], O_RDWR | O_CREAT, 0666);
	Elf* dest  = elf_begin(outfd, ELF_C_WRITE, NULL);
	ELF_ASSERT(dest);
	elf32_getehdr(ve->elf)->e_type = htole16(ET_SCE_RELEXEC);
	ASSERT(!elf_dup(ve->elf, dest));

	size_t shstrndx;
	ELF_ASSERT(!elf_getshdrstrndx(dest, &shstrndx));
	ASSERT(!elf_scndup(dest, shstrndx));

	ASSERT(!sce_elf_discard_invalid_relocs(ve, ve->rela_tables));
	ASSERT(!sce_elf_write_module_info(dest, ve, &section_sizes, encoded_modinfo));
	rtable.next         = ve->rela_tables;
	void* encoded_relas = calloc(sce_elf_count_rela_sections(&rtable), 12);
	ASSERT(encoded_relas);
	ASSERT(!sce_elf_write_rela_sections(dest, ve, &rtable, encoded_relas));
	ASSERT(!sce_elf_rewrite_stubs(dest, ve));

	ELF_ASSERT(elf_update(dest, ELF_C_WRITE) >= 0);
	ELF_ASSERT(!elf_end(dest));
	//lseek(outfd, 0, SEEK_SET);
	//char outbuf[PIPE_BUF];
	//for (ssize_t ret = 0; (ret = read(outfd, &outbuf, sizeof(outbuf))) > 0; write(STDOUT_FILENO, outbuf, ret))
	//	;
	//unlink(tmp_path);
	close(outfd);

	return 0;
}
