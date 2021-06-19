/**
# NAME

psv-self - Generate a (Fake) Signed ELF

# SYNOPSIS

    psv-self [--help] [OPTIONS] <in.velf >out.self

# OPTIONS

Use `psv-self --help` to get a list of possible OPTIONS

# EXAMPLES

    psv-self < in.velf > out.self
    psv-self --authid=2  < in.velf > safe.self

# SEE ALSO
  - self(5)
*/
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elf.h"
#include "self.h"
#include "velf.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#define DEBUG(FMT, ...) getenv("DEBUG") && fprintf(stderr, FMT "\n", __VA_ARGS__);
#ifndef USAGE
#define USAGE "See man psv-self\n"
#endif
#define countof(array) (sizeof(array) / sizeof(*(array)))

#define MAX_PHDR 8 // 2 IRL

typedef struct {
	uint32_t dummy;
	char*    help;
	void*    val;
} opt_ex;
enum { HELP = 0, AUTH, VNDR, STYP, HDRV, APPV, SDKT, TYPE }; /* for a sexier access to options[] */
struct option options[] = {
    /*name,hasArg,          defaultVal, description (for --help screen), value if found */
    {"help", 0, (int*)&(opt_ex){0, "display this help and exit"}, 1},
    {"authid", 1, (int*)&(opt_ex){1, "1:normal 2:safe 3:secret"}},
    {"vendorid", 1, (int*)&(opt_ex){0, "vendor id"}},
    {"selftype", 1, (int*)&(opt_ex){8, "1:lv0 2:lv1 3:lv2 4:app 5:SPU 6:secldr 7:appldr 8:NPDRM"}},
    {"ver_hdr", 1, (int*)&(opt_ex){3, "version (header)"}},
    {"ver_app", 1, (int*)&(opt_ex){0, "version (appinfo)"}},
    {"sdktype", 1, (int*)&(opt_ex){192, "SDK type"}},
    {"type", 1, (int*)&(opt_ex){1, "1:self 2:? 3:pkg"}},
    {}};

ssize_t readn(int fd, void* buf, size_t nbytes) {
	ssize_t remain = nbytes, ret;
	while (remain > 0 && (ret = read(fd, buf + nbytes - remain, (size_t)remain)) > 0) {
		remain -= ret;
	}
	return ret < 0 ? ret : nbytes;
}

int main(int argc, char** argv) {
	/* load arguments */
	for (int i = 0; getopt_long_only(argc, argv, "", options, &i) != -1;) {
		if (options[i].has_arg)
			*options[i].flag = (int)strtol(optarg, NULL, 0);
	}

	if (*options[HELP].flag) {
		for (struct option* opt = options; opt->name; opt++) {
			char line[32] = {};
			snprintf(line, sizeof(line) - 1, "%s%s%.*i", opt->name, opt->has_arg ? "=" : " ", opt->has_arg, opt->has_arg ? *opt->flag : 0);
			fprintf(stderr, "  --%-16s%s\n", line, ((opt_ex*)opt->flag)->help);
		}
		return -1;
	}
	if ((argc - optind) > 0 || isatty(STDIN_FILENO) || isatty(STDOUT_FILENO)) {
		return fprintf(stderr, "%s", USAGE);
	}

	Elf32_Ehdr ehdr;
	ssize_t    consumed = readn(STDIN_FILENO, &ehdr, sizeof(ehdr));
	EXPECT((ehdr.e_type == ET_SCE_EXEC) || (ehdr.e_type == ET_SCE_RELEXEC), "not a SCE(REL)EXEC .velf file");

	Elf32_Phdr phdr[MAX_PHDR];
	EXPECT(ehdr.e_phoff == ehdr.e_ehsize && ehdr.e_phentsize == sizeof(*phdr) && ehdr.e_phnum < countof(phdr), "bad phdr");
	consumed += readn(STDIN_FILENO, &phdr, ehdr.e_phnum * sizeof(*phdr));

	// bool is_rel = (ehdr->e_type == ET_SCE_RELEXEC);
	// write module nid
	// Elf32_Phdr          *phdr = (Elf32_Phdr*          )(elf_data + ehdr->e_phoff  + (is_rel?(ehdr->e_entry >>
	// 30)*ehdr->e_phentsize:0)); sce_module_info_t   *info = (sce_module_info_t   *)(elf_data + phdr->p_offset +
	// (is_rel?(ehdr->e_entry & 0x3fffffff):phdr->p_paddr)); info->library_nid =
	// SHA256_Final(SHA256_Update(SHA256_Init(&(SHA256_CTX){}), elf_data, elf_size),NULL);//htole32?

	SELF_header self = {
	    .magic           = SELF_HEADER_MAGIC, // "SCE\0"
	    .version         = (uint32_t)*options[HDRV].flag,
	    .sdk_type        = (uint16_t)*options[SDKT].flag,
	    .header_type     = (uint16_t)*options[TYPE].flag,
	    .metadata_offset = 0x600,  // ???
	    .header_len      = 0x1000, // wiki say 0x100 ? TODO: Be more precise
	    .elf_filesize    = ehdr.e_shoff + (ehdr.e_shnum * ehdr.e_shentsize),
	    .ctrl_size       = sizeof(SELF_npdrm) + sizeof(SELF_boot) + sizeof(SELF_secret),
	};
	self.self_offset       = 4, // TODO ?
	    self.app_offset    = 0 + sizeof(SELF_header);
	self.elf_offset        = self.app_offset + sizeof(SELF_app);
	self.phdr_offset       = ((self.elf_offset + sizeof(Elf32_Ehdr)) + 0xf) & ~0xf; // align
	self.section_offset    = self.phdr_offset + sizeof(Elf32_Phdr) * ehdr.e_phnum;
	self.sceversion_offset = self.section_offset + sizeof(SELF_segment) * ehdr.e_phnum;
	self.ctrl_offset       = self.sceversion_offset + sizeof(SELF_version);
	self.self_filesize     = /*self.ctrl_offset + self.ctrl_size*/ self.header_len + self.elf_filesize;
	write(STDOUT_FILENO, &self, sizeof(self));

	SELF_app self_app = {
	    .authid    = *options[AUTH].flag | (0x2FLLU << 56),
	    .vendor_id = *options[VNDR].flag | 0U,
	    .self_type = *options[STYP].flag | 0U,
	    .version   = *options[APPV].flag | (1LLU << 48),
	    .padding   = 0,
	};
	write(STDOUT_FILENO, &self_app, sizeof(self_app));

	Elf32_Ehdr sehdr = ehdr;
	sehdr.e_flags    = 0x05000000U;
	sehdr.e_shoff = sehdr.e_shentsize = sehdr.e_shnum = sehdr.e_shstrndx = 0;
	write(STDOUT_FILENO, &sehdr, sizeof(sehdr));

	write(STDOUT_FILENO, &(char[16]){}, self.phdr_offset - (self.elf_offset + sizeof(Elf32_Ehdr)));

	for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
		if (phdr[i].p_align > 0x1000) {
			DEBUG("truncate phdr[%i] to 0x1000, was %x", i, phdr[i].p_align);
			phdr[i].p_align = 0x1000;
		}
		write(STDOUT_FILENO, phdr + i, sizeof(*phdr));
	}

	for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
		SELF_segment self_segment = {
		    .offset      = self.header_len + phdr[i].p_offset,
		    .length      = phdr[i].p_filesz,
		    .compression = SELF_SEGMENT_UNCOMPRESSED,
		    .encryption  = SELF_SEGMENT_PLAIN,
		};
		write(STDOUT_FILENO, &self_segment, sizeof(self_segment));
	}
	write(STDOUT_FILENO, &(SELF_version){1, 0, 16, 0}, sizeof(SELF_version));
	write(STDOUT_FILENO, &(SELF_npdrm){{5, sizeof(SELF_npdrm), 1}}, sizeof(SELF_npdrm));
	write(STDOUT_FILENO, &(SELF_boot){{6, sizeof(SELF_boot), 1}, 1}, sizeof(SELF_boot));
	write(STDOUT_FILENO, &(SELF_secret){{7, sizeof(SELF_secret)}}, sizeof(SELF_secret));
	// fill up to self.header_len
	for (unsigned i = 0; i < self.header_len - (self.ctrl_offset + self.ctrl_size); i++) {
		write(STDOUT_FILENO, "\0", 1);
	}

	char buf; // TODO: bigger buffer => less iteration
	write(STDOUT_FILENO, &ehdr, sizeof(ehdr));
	write(STDOUT_FILENO, &phdr, ehdr.e_phnum * sizeof(*phdr));
	for (size_t remain = self.elf_filesize - consumed; remain > 0; remain--) {
		readn(STDIN_FILENO, &buf, sizeof(buf));
		write(STDOUT_FILENO, &buf, sizeof(buf));
	}
	return 0;
}
