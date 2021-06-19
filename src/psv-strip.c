/**
# NAME

psv-strip - strip a Vita ELF

# SYNOPSIS

    psv-strip in.velf out.velf

# NOTES

does not seems to work on every case

# CREDIT

- github.com/Princess-of-Sleeping

# SEE ALSO
  - velf(5)
*/
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#ifndef USAGE
#define USAGE "See man psv-pack\n"
#endif

int pack_velf(FILE* fd_src, FILE* fd_dst) {

	char buf[0x100];

	EXPECT(fread(buf, sizeof(buf), 1, fd_src) == 1, "Bad ELF header size");

	/*
	 * Remove section entrys
	 */
	Elf32_Ehdr* elf_header  = (Elf32_Ehdr*)buf;
	elf_header->e_shoff     = 0;
	elf_header->e_shentsize = 0;
	elf_header->e_shnum     = 0;
	elf_header->e_shstrndx  = 0;

	Elf32_Phdr* pPhdr = (Elf32_Phdr*)(buf + elf_header->e_phoff);

	/*
	 * Packed ehdr and phdr
	 */
	if (elf_header->e_phoff != elf_header->e_ehsize) {
		Elf32_Phdr* pPhdrTmp = malloc(elf_header->e_phentsize * elf_header->e_phnum);

		memcpy(pPhdrTmp, pPhdr, elf_header->e_phentsize * elf_header->e_phnum);

		memset(buf + elf_header->e_ehsize, 0, sizeof(buf) - elf_header->e_ehsize);
		memcpy(buf + elf_header->e_ehsize, pPhdrTmp, elf_header->e_phentsize * elf_header->e_phnum);

		free(pPhdrTmp);

		elf_header->e_phoff = elf_header->e_ehsize;
		pPhdr               = (Elf32_Phdr*)(buf + elf_header->e_phoff);
	}

	long seg_offset = elf_header->e_ehsize + (elf_header->e_phentsize * elf_header->e_phnum);

	/*
	 * Write packed elf header
	 */
	fseek(fd_dst, 0, SEEK_SET);
	EXPECT(fwrite(buf, seg_offset, 1, fd_dst) == 1, "Unable to write packed elf header");

	/*
	 * Write elf segments
	 */
	for (int i = 0; i < elf_header->e_phnum; i++) {

		/*
		 * vita only accepts 0x10 to 0x1000 alignments
		 */
		if (pPhdr[i].p_align > 0x1000) {
			pPhdr[i].p_align = 0x10; // vita elf default align
		}

		seg_offset = (seg_offset + (pPhdr[i].p_align - 1)) & ~(pPhdr[i].p_align - 1);

		if (pPhdr[i].p_filesz != 0) {
			void* seg_tmp = malloc(pPhdr[i].p_filesz);

			fseek(fd_dst, seg_offset, SEEK_SET);
			fseek(fd_src, pPhdr[i].p_offset, SEEK_SET);
			EXPECT(fread(seg_tmp, pPhdr[i].p_filesz, 1, fd_src) == 1, "Unable to read pHdr[%i]", i);
			EXPECT(fwrite(seg_tmp, pPhdr[i].p_filesz, 1, fd_dst) == 1, "Unable to read pHdr[%i]", i);
			free(seg_tmp);
			seg_tmp = NULL;
		}

		pPhdr[i].p_offset = seg_offset;
		seg_offset += pPhdr[i].p_filesz;
	}

	seg_offset = elf_header->e_ehsize + (elf_header->e_phentsize * elf_header->e_phnum);

	/*
	 * Write updated elf header
	 */
	fseek(fd_dst, 0, SEEK_SET);
	EXPECT(fwrite(&buf, seg_offset, 1, fd_dst) == 1, "Unable to write final ELF");
	return 0;
}

int main(int argc, char** argv) {
	EXPECT(argc > 2, "%s", USAGE);

	FILE* fd_src = fopen(argv[1], "rb");
	EXPECT(fd_src, "Unable to open input file");

	FILE* fd_dst = fopen(argv[2], "wb");
	EXPECT(fd_dst, "Unable to open output file"); // cppcheck-suppress resourceLeak

	pack_velf(fd_src, fd_dst);

	fclose(fd_dst);
	fclose(fd_src);

	return 0;
}
