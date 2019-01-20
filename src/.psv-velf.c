/*
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
- Update p_paddr of the first segment to point to the module info (for ET_SCE_EXEC types) or e_entry to point to the
module info (for ET_SCE_RELEXEC types).
- Write import stubs over the temporary entries in.vitalink.fstubs and .vitalink.vstubs.
- Copy over the other program segments (if needed).
- Create a new program segment of type PT_SCE_RELA and create SCE relocation entries based on the ELF relocation entries
of the input ELF.
*/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <malloc.h>
#include "elf.h"
#include "velf.h"

#define expect(COND,fmt...) \
	if (!(COND)) \
		return fputs("\nexpect("#COND") failed ",stderr),fprintf(stderr, " " fmt), -1;
#define  startswith(STR, TOK) !strncmp(STR, TOK, strlen(TOK))
#define SECNAME_FSTUB ".vitalink.fstubs."
#define SECNAME_VSTUB ".vitalink.vstubs."

static void read_fifo(int fd, int* len, void** buf) {
	const size_t LEN = 32;
	for (ssize_t ret = LEN; ret == LEN; *len += (ret = read(fd, *buf + *len, LEN))) {
		*buf = realloc(*buf, *len + LEN);
	}
}

static int is_valid_relsection(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr) {
	expect(shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA);
	expect(ehdr->e_phnum);
	shdr->sh_size = (shdr->sh_type == SHT_NOBITS) ? shdr->sh_size : 0;
	// TODO: check splitted sec across multiple pseg
	for (Elf32_Phdr* phdr = elf_phdr(ehdr), *last = phdr + ehdr->e_phnum; phdr < last; phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;
		// TODO: Take account of possible integer wrap-arounds
		if (phdr->p_offset <= shdr->sh_offset && shdr->sh_offset + shdr->sh_size <= phdr->p_offset + phdr->p_filesz)
			return 1;
	}
	return 0;
}

static int load_stubs(Elf32_Ehdr* ehdr, Elf32_Shdr* shdr, char *libname) {
	expect(shdr->sh_size % sizeof(velf_stub) == 0, "unaligned stubs section");
	//TODO: expect(shdr->sh_entsize == sizeof(velf_stub)), currently 0, see psv-deb.c
	for (velf_stub* stub = (velf_stub*)elf_sdata(ehdr, shdr), *last = stub + shdr->sh_size / sizeof(*stub); stub < last; stub++) {
		printf("%s %08X %08X %08X %08X\n", libname, stub->flags, stub->modnid, stub->symnid, stub->unk);
	}
	return 0;
}

static int load_symbols(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr) {
	expect(shdr->sh_size % sizeof(Elf32_Sym) == 0, "unaligned stubs section");
	expect(shdr->sh_entsize == sizeof(Elf32_Sym), "bad sh_entsize");
	for (Elf32_Sym* sym = (Elf32_Sym*)elf_sdata(ehdr, shdr), *last = sym + shdr->sh_size / sizeof(Elf32_Sym); sym < last; sym++) {
		printf("Symbol: %08X%6i %c       %c      %7X %4X %-8.X\n", sym->st_value, sym->st_size, "NOFSf56789ABCDEF"[sym->st_info&0xF], "LGW3456789ABCDEF"[sym->st_info>>4], sym->st_other, sym->st_shndx, sym->st_name);
	}
	return 0;
}

static int get_rel_handling(int type) {
	switch(type) {
		case R_ARM_NONE:
		case R_ARM_V4BX:
			return 1;
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
			return 0;
		default:return -1;
	}
}

static int load_rel_table(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr) {
	expect(!load_symbols(ehdr, elf_shdr(ehdr, shdr->sh_link)));
	//uint8_t *text = elf_sdata(ehdr, elf_shdr(ehdr, shdr->sh_info));

	for (Elf32_Rel* rel = (Elf32_Rel *) elf_sdata(ehdr, shdr), *last = rel + shdr->sh_size / shdr->sh_entsize; rel > last; rel++) {
		printf("type = %4X @ %08X\n", rel->r_type, rel->r_offset);
		if (rel->r_type == R_ARM_THM_JUMP24)
			rel->r_type = R_ARM_THM_CALL;
		if (rel->r_type == R_ARM_THM_PC11)
			continue;
		/* Use memcpy for unaligned relocation. */
		// memcpy(&insn, text_data->d_buf+(rel.r_offset - text_shdr.sh_addr), sizeof(insn));

		int handling = get_rel_handling(rel->r_type);
		expect(handling >= 0);
		if (handling > 0)
			continue;
#if 0
		int rel_sym = GELF_R_SYM(rel.r_info);
		ASSERT(rel_sym < ve->num_symbols, "REL entry tried to access symbol %d, but only %d symbols loaded", rel_sym, ve->num_symbols);

		currela->symbol = ve->symtab + rel_sym;

		if((target = decode_rel_target(insn, currela->type, rel.r_offset)) == ~0)
			goto failure;

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
#endif
	}

	return 0;
}

int main(int argc, char** argv) {
	if (isatty(STDIN_FILENO)) {
		return printf("nothing on stdin\nUSAGE:\n"), -1;
	}
	void* buf  = NULL;
	int   size = 0;
	read_fifo(STDIN_FILENO, &size, &buf);
	Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buf;
	expect(ehdr->e_machine == EM_ARM);
	expect(ehdr->e_ident[EI_CLASS] == ELFCLASS32);
	expect(ehdr->e_ident[EI_DATA] == ELFDATA2LSB);

	size_t fstubs = 0, vstubs = 0;
	for (Elf32_Shdr*shdr = elf_shdr(ehdr), *last = shdr+ehdr->e_shnum; shdr < last; shdr++) {
		char* secname = elf_sname(ehdr, shdr);
		printf("\n%s\n",secname);
		if (shdr->sh_type == SHT_SYMTAB) {
			expect(!load_symbols(ehdr, shdr));
		} else if (shdr->sh_type == SHT_PROGBITS && startswith(secname, SECNAME_FSTUB)) {
			expect(!load_stubs(ehdr, shdr, secname + strlen(SECNAME_FSTUB)));
		} else if (shdr->sh_type == SHT_PROGBITS && startswith(secname, SECNAME_VSTUB)) {
			expect(!load_stubs(ehdr, shdr, secname + strlen(SECNAME_VSTUB)));
		} else if (shdr->sh_type == SHT_REL && is_valid_relsection(ehdr, shdr)) {
			expect(!load_rel_table(ehdr, shdr));
		} else if (shdr->sh_type == SHT_RELA && is_valid_relsection(ehdr, shdr)) {
			//expect(!load_rela_table(ehdr, shdr));
		}
	}
	if (fstubs != 0) {
		//expect(lookup_stub_symbols(ve, ve->num_fstubs, ve->fstubs, &ve->fstubs_va, STT_FUNC));
	}

	if (vstubs != 0) {
		//expect(lookup_stub_symbols(ve, ve->num_vstubs, ve->vstubs, &ve->vstubs_va, STT_OBJECT));
	}

	//lookup_stub_symbols()
//	if (isatty(STDOUT_FILENO)) {
//		return 0;
//	}
//	printf("convert");
	return 0;
}