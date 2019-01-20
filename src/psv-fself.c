#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elf.h"
#include "self.h"
#include "sha256.h"
#include "velf.h"

#define EXPECT(EXPR, FMT, ...)                            \
	if (!(EXPR)) {                                    \
		fprintf(stderr, FMT "\n", ##__VA_ARGS__); \
		return -1;                                \
	}
#define USAGE "Usage: %s [OPTIONS] <in.velf >out.fself\nOPTIONS:\n"
#define VPK_FIFO_LEN 32

typedef struct {
	int   dummy;
	char* help;
	void* val;
} opt_ex;
enum { HELP = 0, AUTH, VNDR, STYP, HDRV, APPV, SDKT, TYPE }; /* for a sexier access to options[] */
struct option options[] = {
    /*name,hasArg,          defaultVal, description (for --help screen), value if found */
    {"help", 0, (int*)&(opt_ex){0, "display this help and exit"}, 1},
    {"authid", 1, (int*)&(opt_ex){1, "1:normal,2:safe,3:secret"}},
    {"vendorid", 1, (int*)&(opt_ex){0, "vendor id"}},
    {"selftype", 1, (int*)&(opt_ex){8, "1:lv0,2:lv1,3:lv2,4:app,5:SPU,6:secldr,7:appldr,8:NPDRM"}},
    {"ver_hdr", 1, (int*)&(opt_ex){3, "version (header)"}},
    {"ver_app", 1, (int*)&(opt_ex){0, "version (appinfo)"}},
    {"sdktype", 1, (int*)&(opt_ex){192, "SDK type"}},
    {"type", 1, (int*)&(opt_ex){1, "1:self,2:?,3:pkg"}},
    {}};

static void read_fifo(int fd, size_t* len, uint8_t** buf) {
	for (int ret = VPK_FIFO_LEN; ret == VPK_FIFO_LEN; *len += (ret = read(fd, *buf + *len, VPK_FIFO_LEN))) {
		*buf = realloc(*buf, *len + VPK_FIFO_LEN);
	}
}

int main(int argc, char** argv) {
	/* load arguments */
	for (int optidx = 0; getopt_long_only(argc, argv, "", options, &optidx) != -1;) {
		if (options[optidx].has_arg)
			options[optidx].val = strtol(optarg, NULL, 0);
	}

	/* print help if requested or non-option arg given or if not piped */
	if (*options[HELP].flag || (argc - optind) > 0 || isatty(STDIN_FILENO) || isatty(STDOUT_FILENO)) {
		fprintf(stderr, USAGE, argv[0]);
		for (struct option* opt = options; opt->name; opt++) {
			char line[32] = {};
			snprintf(line, sizeof(line) - 1, "%s%s%.*i", opt->name, opt->has_arg ? "=" : " ", opt->has_arg,
				 opt->has_arg ? *opt->flag : 0);
			fprintf(stderr, "  --%-16s%s\n", line, ((opt_ex*)opt->flag)->help);
		}
		return -1;
	}

	uint8_t* elf_data = NULL;
	size_t   elf_size = 0;
	read_fifo(STDIN_FILENO, &elf_size, &elf_data);
	Elf32_Ehdr* ehdr = (Elf32_Ehdr*)elf_data;
	EXPECT((ehdr->e_type == ET_SCE_EXEC) || (ehdr->e_type == ET_SCE_RELEXEC), "not a SCE(REL)EXEC .velf file")

	// bool is_rel = (ehdr->e_type == ET_SCE_RELEXEC);
	// write module nid
	// Elf32_Phdr          *phdr = (Elf32_Phdr*          )(elf_data + ehdr->e_phoff  + (is_rel?(ehdr->e_entry >>
	// 30)*ehdr->e_phentsize:0)); sce_module_info_t   *info = (sce_module_info_t   *)(elf_data + phdr->p_offset +
	// (is_rel?(ehdr->e_entry & 0x3fffffff):phdr->p_paddr)); info->library_nid =
	// SHA256_Final(SHA256_Update(SHA256_Init(&(SHA256_CTX){}), elf_data, elf_size),NULL);//htole32?

	SELF_header self = {
	    .magic           = 0x454353, // "SCE\0"
	    .version         = *options[HDRV].flag,
	    .sdk_type        = *options[SDKT].flag,
	    .header_type     = *options[TYPE].flag,
	    .metadata_offset = 0x600,  // ???
	    .header_len      = 0x1000, // wiki say 0x100 ? TODO: Be exact
	    .elf_filesize    = elf_size,
	    .self_offset     = 4, // TODO ?
	    .ctrl_size       = sizeof(SELF_ctrl_5) + sizeof(SELF_ctrl_6) + sizeof(SELF_ctrl_7),
	};
	self.app_offset        = 0 + sizeof(SELF_header);
	self.elf_offset        = self.app_offset + sizeof(SELF_app);
	self.phdr_offset       = ((self.elf_offset + sizeof(Elf32_Ehdr)) + 0xf) & ~0xf; // align
	self.section_offset    = self.phdr_offset + sizeof(Elf32_Phdr) * ehdr->e_phnum;
	self.sceversion_offset = self.section_offset + sizeof(SELF_segment) * ehdr->e_phnum;
	self.ctrl_offset       = self.sceversion_offset + sizeof(SELF_version);
	self.self_filesize     = /*self.ctrl_offset + self.ctrl_size*/ 0x1000 + self.elf_filesize;
	write(STDOUT_FILENO, &self, sizeof(self));

	write(STDOUT_FILENO,
	      &(SELF_app){
		  .authid    = *options[AUTH].flag | (0x2FLLU << 56),
		  .vendor_id = *options[VNDR].flag,
		  .self_type = *options[STYP].flag,
		  .version   = *options[APPV].flag | (1LLU << 48),
		  .padding   = 0,
	      },
	      sizeof(SELF_app));

	write(STDOUT_FILENO,
	      &(Elf32_Ehdr){
		  .e_ident     = "\177ELF\1\1\1\0",
		  .e_type      = ehdr->e_type,
		  .e_machine   = ehdr->e_machine,
		  .e_version   = ehdr->e_version,
		  .e_entry     = ehdr->e_entry,
		  .e_phoff     = ehdr->e_phoff,
		  .e_shoff     = 0,
		  .e_flags     = 0x05000000U,
		  .e_ehsize    = ehdr->e_ehsize,
		  .e_phentsize = ehdr->e_phentsize,
		  .e_phnum     = ehdr->e_phnum,
		  .e_shentsize = 0,
		  .e_shnum     = 0,
		  .e_shstrndx  = 0,
	      },
	      sizeof(Elf32_Ehdr));

	write(STDOUT_FILENO, &(char[16]){}, self.phdr_offset - (self.elf_offset + sizeof(Elf32_Ehdr)));

	for (int i = 0; i < ehdr->e_phnum; ++i) {
		Elf32_Phdr* phdr = (Elf32_Phdr*)(elf_data + ehdr->e_phoff + ehdr->e_phentsize * i);
		if (phdr->p_align > 0x1000)
			phdr->p_align = 0x1000;
		write(STDOUT_FILENO, phdr, sizeof(*phdr));
	}

	for (int i = 0; i < ehdr->e_phnum; ++i) {
		Elf32_Phdr* phdr = (Elf32_Phdr*)(elf_data + ehdr->e_phoff + ehdr->e_phentsize * i);
		write(STDOUT_FILENO,
		      &(SELF_segment){
			  .offset      = self.header_len + phdr->p_offset,
			  .length      = phdr->p_filesz,
			  .compression = SELF_SEGMENT_UNCOMPRESSED,
			  .encryption  = SELF_SEGMENT_PLAIN,
		      },
		      sizeof(SELF_segment));
	}
	write(STDOUT_FILENO, &(SELF_version){1, 0, 16, 0}, sizeof(SELF_version));
	write(STDOUT_FILENO, &(SELF_ctrl_5){{5, sizeof(SELF_ctrl_5), 1}}, sizeof(SELF_ctrl_5));
	write(STDOUT_FILENO, &(SELF_ctrl_6){{6, sizeof(SELF_ctrl_6), 1}, 1}, sizeof(SELF_ctrl_6));
	write(STDOUT_FILENO, &(SELF_ctrl_7){{7, sizeof(SELF_ctrl_7)}}, sizeof(SELF_ctrl_7));
	// fill up to self.header_len
	for (unsigned i = 0; i < self.header_len - (self.ctrl_offset + self.ctrl_size); i++) {
		write(STDOUT_FILENO, "\0", 1);
	}

	write(STDOUT_FILENO, elf_data, elf_size);
	return 0;
}
