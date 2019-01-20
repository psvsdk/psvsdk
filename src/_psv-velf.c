#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>

#include <libelf.h>
#include "velf2.h"
#include "export.h"
#include "sce-elf.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#define USAGE \
	"Usage: %s [-e export.yml] <a.elf >a.velf\n\n\
EXAMPLES\n\
	%s < a.out > main.velf\n\
	%s -e main.yml < a.out > main.velf\n"

void elf_utils_free_scn_contents(Elf *e, int scndx) {
	Elf_Scn *scn;
	Elf_Data *data;

	ELF_ASSERT(scn = elf_getscn(e, scndx));

	data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		free(data->d_buf);
		data->d_buf = NULL;
	}

	failure:
	return;
}
int elf_scndup(Elf *e, size_t scndx) {
	Elf_Scn *scn = elf_getscn(e, scndx);
	ELF_ASSERT(scn);
	for(Elf_Data *data = NULL;(data = elf_getdata(scn, data)); ) {
		void *new_data = malloc(data->d_size);
		ASSERT(new_data);
		memcpy(new_data, data->d_buf, data->d_size);
		data->d_buf = new_data;
	}

	return 1;
	failure:
	return 0;
}

/* Generate a dest elf with, same ehdr, dup sections (header+data), dup phdrs as src*/
int elf_dup(Elf *source, Elf *dest) {
	ELF_ASSERT(elf_flagelf(dest, ELF_C_SET, ELF_F_LAYOUT));

	GElf_Ehdr ehdr;
	ELF_ASSERT(gelf_getehdr(source, &ehdr));
	ELF_ASSERT(gelf_newehdr(dest, gelf_getclass(source)));
	ELF_ASSERT(gelf_update_ehdr(dest, &ehdr));

	for(Elf_Scn *dst_scn, *src_scn = NULL; (src_scn = elf_nextscn(source, src_scn)); ) {
		GElf_Shdr src_shdr;
		ELF_ASSERT(gelf_getshdr(src_scn, &src_shdr));
		ELF_ASSERT(dst_scn = elf_newscn(dest));
		ELF_ASSERT(gelf_update_shdr(dst_scn, &src_shdr));

		for (Elf_Data *src_data = NULL; (src_data = elf_getdata(src_scn, src_data)); ) {
			Elf_Data *dst_data = elf_newdata(dst_scn);
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

	return 1;
	failure:
	return 0;
}

int main(int argc, char *argv[]) {
	EXPECT(!isatty(STDIN_FILENO), USAGE, argv[0], argv[0], argv[0]);
	vita_export_t exports = {.ver_major = 1, .ver_minor = 1, .nid = 0x00000000, .name = ""};

	vita_elf_t *ve = vita_elf_load(STDIN_FILENO); ASSERT(ve);
	vita_elf_lookup_imports(ve);
	sce_module_info_t *module_info = sce_elf_module_info_create(ve, &exports); ASSERT(module_info);
	sce_section_sizes_t section_sizes;
	sce_elf_module_info_get_size(module_info, &section_sizes);
	vita_elf_rela_table_t rtable = {};
	void *encoded_modinfo = sce_elf_module_info_encode(module_info, ve, &section_sizes, &rtable);

	char* tmp_path = "/tmp/.velf";
	int outfd = open(tmp_path, O_RDWR | O_CREAT, 0666);
	elf32_getehdr(ve->elf)->e_type = htole16(ET_SCE_RELEXEC);
	Elf *dest = elf_begin(outfd, ELF_C_WRITE, NULL);
	ELF_ASSERT(dest);
	ASSERT(elf_dup(ve->elf, dest));

	size_t shstrndx;
	ELF_ASSERT(elf_getshdrstrndx(dest, &shstrndx) == 0);
	ASSERT(elf_scndup(dest, shstrndx));

	ASSERT(sce_elf_discard_invalid_relocs(ve, ve->rela_tables));
	ASSERT(sce_elf_write_module_info(dest, ve, &section_sizes, encoded_modinfo));
	rtable.next = ve->rela_tables;
	ASSERT(sce_elf_write_rela_sections(dest, ve, &rtable));
	ASSERT(sce_elf_rewrite_stubs(dest, ve));

	ELF_ASSERT(elf_update(dest, ELF_C_WRITE) >= 0);

	elf_end(dest);
	lseek(outfd, 0, SEEK_SET);
	char outbuf[PIPE_BUF];
	for (ssize_t ret = 0; (ret = read(outfd, &outbuf, sizeof(outbuf))) > 0; write(STDOUT_FILENO, outbuf, ret));
	close(outfd);
	unlink(tmp_path);

	return EXIT_SUCCESS;
	failure:
	return EXIT_FAILURE;
}
