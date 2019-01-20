#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "yml.h"

#define countof(array) (sizeof(array) / sizeof(*array))
#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#define USAGE \
	"Usage: %s ACTION <db.yml\n\n\
ACTION\n\
	- libgen # write stubs and print lib *.a build commands for sh piping\n\
	- dump   # print module,lib,export for grep,wc,awk piping\n\
EXAMPLES\n\
	%s libgen<db.yml|sh # default tools (arm-vita-eabi-*)\n\
	RM=echo %s libgen<db.yml|sh # custom tools {AS,AR,RANLIB,RM}\n\
	%s dump<db.yml\n"
//TODO: specify entsize (4) after %%progbits
#define ASM_ENTRY_ASM(t, p, type) \
	".arch armv7a\n\
.section .vitalink." t "stubs.%s,\"a" p "\",%%progbits\n\
	.align 4\n\
	.global %s\n\
	.type %s, %%" type "\n\
%s:\n\
.if GEN_WEAK_EXPORTS\n\
	.word 0x00000008\n\
.else\n\
	.word 0x00000000\n\
.endif\n\
	.word 0x%08X\n\
	.word 0x%08X\n\
	.align 4\n\n"

#define DB_ASM_FUN ASM_ENTRY_ASM("f", "x", "object")
#define DB_ASM_VAR ASM_ENTRY_ASM("v", "w", "function")

typedef struct {
	char lib[YML_MAX_LIBNAME];
	int  fd;
} yml_ctx_cb;

static void libgen(void* ctx_, yml_db_line yml) {
	yml_ctx_cb* ctx = (yml_ctx_cb*)ctx_;
	if (yml.lib_name && !yml.exp_name) {
		ctx->fd = open(yml.lib_name, O_WRONLY | O_CREAT, 0666);
		memcpy(ctx->lib, yml.lib_name, YML_MAX_LIBNAME);
	} else if (yml.exp_name) {
		dprintf(ctx->fd, DB_ASM_FUN, yml.mod_name, yml.exp_name, yml.exp_name, yml.exp_name, yml.mod_nid,
			yml.exp_nid);
	} else if (!yml.exp_name && ctx->fd) {
		close(ctx->fd);
		ctx->fd = 0;
		for (char** weak = (char*[]){"", "_weak", 0}; *weak; weak++) {
			printf("%s --defsym GEN_WEAK_EXPORTS=%i %s -o %s%s.o\n", getenv("AS") ?: "arm-vita-eabi-as",
			       **weak ? 1 : 0, ctx->lib, ctx->lib, *weak);
			printf("%s cru lib%s_stub%s.a %s%s.o\n", getenv("AR") ?: "arm-vita-eabi-ar", ctx->lib, *weak,
			       ctx->lib, *weak);
			printf("%s lib%s_stub%s.a\n", getenv("RANLIB") ?: "arm-vita-eabi-ranlib", ctx->lib, *weak);
			printf("%s %s%s.o\n", getenv("RM") ?: "rm", ctx->lib, *weak);
		}
		printf("%s %s\n", getenv("RM") ?: "rm", ctx->lib);
	}
}

static void dump(void* unused, yml_db_line yml) {
	(void)unused;
	if (!yml.exp_name)
		return;
	printf("%08X %-25s %08X %-25s %s %08X %s\n", yml.mod_nid, yml.mod_name, yml.lib_nid, yml.lib_name,
	       yml.lib_kernel ? "k" : "u", yml.exp_nid, yml.exp_name);
}

int main(int argc, char** argv) {
	EXPECT(!isatty(STDIN_FILENO) && argc >= 2, USAGE, argv[0], argv[0], argv[0], argv[0]);
	yml_walker_cb cb = ((yml_walker_cb[]){['d'] = dump, ['l'] = libgen})[(int)argv[1][0]];
	EXPECT(cb, "unknown ACTION '%s'", argv[1]);
	yml_ctx_cb ctx = {};
	yml_walker(STDIN_FILENO, cb, &ctx);
	return 0;
}