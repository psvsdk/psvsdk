/**
# NAME
  psv-db - Vita NID database line-based utility

# SYNOPSIS
	psv-db < db.yml

# OUTPUT
  The output is column based for easy post-processing (awk, grep, sed ...) :

	fw  ModNID ModName  LibNID LibName LibPrivilege  FuncNID FuncName

# EXAMPLES

	psv-db < db.yml | grep -P 'For(Kernel|Driver) +u' # check that *ForKernel/*ForDriver library don't export for users
	psv-db < db.yml | grep -P ' k ' | grep -Pv 'For(Driver|Kernel)' # check that no kernel exports are outside a ForDriver/Kernel lib
	psv-db < db.yml | awk '$7~/4B171BEA/{print "lib"$3"_"$1".a:"$8}' # find a NID (4B171BEA) and print it lib + name

# SEE ALSO
  - yml(5)
  - psv-lib(1)

*/
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
#ifndef USAGE
#define USAGE "See man psv-db\n"
#endif
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

/*
static void libgen(void* ctx_, yml_db_line yml) {
	char* as = getenv("AS") ?: "arm-vita-eabi-as";
	char* ar = getenv("AR") ?: "arm-vita-eabi-ar";
	char* rl = getenv("RANLIB") ?: "arm-vita-eabi-ranlib";
	char* rm = getenv("RM") ?: "rm";

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
			printf("%s --defsym GEN_WEAK_EXPORTS=%i %s -o %s%s.o\n", as, **weak ? 1 : 0, ctx->lib, ctx->lib, *weak);
			printf("%s cru lib%s_stub%s.a %s%s.o\n", ar, ctx->lib, *weak, ctx->lib, *weak);
			printf("%s lib%s_stub%s.a\n", rl, ctx->lib, *weak);
			printf("%s %s%s.o\n", rm, ctx->lib, *weak);
		}
		printf("%s %s\n", rm, ctx->lib);
	}
}
*/
static void dump(void* ctx, yml_db_line yml) {
	if (!yml.exp_name)
		return;
	printf("%i %08X %-25s %08X %-25s %s %08X %s\n", yml.yml_firmware,
	       yml.mod_nid, yml.mod_name,
	       yml.lib_nid, yml.lib_name, yml.lib_kernel ? "k" : "u",
	       yml.exp_nid, yml.exp_name);
}

int main(int argc, char** argv) {
	EXPECT(!isatty(STDIN_FILENO), "No file on stdin\n" USAGE);
	yml_walker(STDIN_FILENO, dump, NULL);
	return 0;
}