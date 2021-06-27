/**
# NAME

psv-velf - Generate a Vita ELF

# SYNOPSIS

    psv-velf in.elf out.velf

# ENVIRONMENT VARIABLES
  - DEBUG (any value): print more details on stderr

# NOTES

A better configuration system shall used
to specify module name,nid,version ...

# SEE ALSO
  - velf(5)
*/
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "velf.h"
#define MAX_SEG  256
#define LOG(...) fprintf(getenv("DEBUG") ? stderr : stdin, __VA_ARGS__)
#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))                 \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;

int main(int argc, char* argv[]) {
	EXPECT(argc == 3, "USAGE: psv-velf in.elf out.velf");
	//TODO: setup libs from file/argv
	//char*         exports_path = "export.yml"; // TODO print/export symbol+nid to yml
	vita_export_t exports = {.name = "a.out", .ver_major = 1, .ver_minor = 1, .nid = 0x12345678};

	velf_t ve = {0};
	velf_load(argv[1], &ve);

	/* FIXME: save original segment sizes */
	EXPECT(ve.num_segments <= MAX_SEG, "Too much segment to remember %i > MAX_SEG (%i)", ve.num_segments, MAX_SEG);
	Elf32_Word segment_sizes[MAX_SEG];
	for (int idx = 0; idx < ve.num_segments; idx++)
		segment_sizes[idx] = ve.segments[idx].memsz;

	//vita_exports_load(args.exports, args.input, 0)
	velf_lookup_imports(&ve); // don't fail if no import found

	if (ve.fstubs_va.count) {
		LOG("Function stubs in sections \n");
		print_stubs(ve.fstubs, ve.num_fstubs);
	}
	if (ve.vstubs_va.count) {
		LOG("Variable stubs in sections \n");
		print_stubs(ve.vstubs, ve.num_vstubs);
	}

	LOG("Relocations:\n");
	list_rels(&ve);

	LOG("Segments:\n");
	list_segments(&ve);

	Elf32_Addr have_libc_addr;
	int        have_libc = get_variable_by_symbol("sceLibcHeapSize", &ve, &have_libc_addr);

	sce_process_param_t process_param = {
	    .size       = sizeof(sce_process_param_raw),
	    .magic      = 0x32505350, // PSP2
	    .version    = 6,
	    .fw_version = PSP2_SDK_VERSION,
	};
	sce_param_libc_t libc_param = {._default_heap_size = 0x40000,
	                               .sce_libc_general   = {
                                     .size       = 0x38,
                                     .unk_0x1C   = 9,
                                     .fw_version = PSP2_SDK_VERSION,
                                 }};

	sce_modinfo_t modinfo = {0};
	velf_modinfo_create(&ve, &modinfo, &exports, &process_param);

	sce_section_sizes_t section_sizes = {0};
	velf_modinfo_compute_size(&modinfo, &section_sizes, have_libc);
	int total_size = velf_modinfo_sum_size(&section_sizes);
	int curpos     = 0;
	LOG("Total SCE data size: %d / 0x%x\n", total_size, total_size);
#define PRINTSEC(name)                                                                                      \
	LOG("  .%s: %d @ %x\n", #name, section_sizes.name, curpos + ve.segments[0].vaddr + ve.segments[0].memsz); \
	curpos += section_sizes.name
	PRINTSEC(sceModuleInfo_rodata);
	PRINTSEC(sceLib_ent);
	PRINTSEC(sceExport_rodata);
	PRINTSEC(sceLib_stubs);
	PRINTSEC(sceImport_rodata);
	PRINTSEC(sceFNID_rodata);
	PRINTSEC(sceFStub_rodata);
	PRINTSEC(sceVNID_rodata);
	PRINTSEC(sceVStub_rodata);
#undef PRINTSEC
	velf_rela_table_t rtable = {0};

	void* modinfo_buf = calloc(1, total_size);
	EXPECT(velf_modinfo_encode(&modinfo, &ve, &section_sizes, &rtable, &process_param, have_libc ? &libc_param : NULL, modinfo_buf),
	       "Unable to seralize module info");
	LOG("Relocations from encoded modinfo:\n");
	print_rtable(&rtable);

	FILE* outfile = fopen(argv[2], "wb");
	EXPECT(outfile, "Could not open %s for writing", argv[2]);

	Elf* dest = elf_begin(fileno(outfile), ELF_C_WRITE, NULL);
	EXPECT(dest, "elf_begin");
	EXPECT(elf_utils_copy(dest, ve.elf), "");
	EXPECT(elf_utils_duplicate_shstrtab(dest), "");
	EXPECT(velf_reloc_table_strip(&ve, ve.rela_tables), "");
	EXPECT(velf_modinfo_write(dest, &ve, &section_sizes, modinfo_buf), "");
	rtable.next = ve.rela_tables;
	EXPECT(velf_rela_table_write(dest, &ve, &rtable), "");
	EXPECT(velf_stubs_rewrite(dest, &ve), "");
	EXPECT(elf_update(dest, ELF_C_WRITE) >= 0, "");
	EXPECT(elf_end(dest) == 0, "");
	EXPECT(velf_type(outfile, ET_SCE_RELEXEC), "");
	fclose(outfile);

	/* FIXME: restore original segment sizes */
	for (int idx = 0; idx < ve.num_segments; idx++)
		ve.segments[idx].memsz = segment_sizes[idx];

	velf_modinfo_free(&modinfo);
	free(modinfo_buf);
	return 0;
}
