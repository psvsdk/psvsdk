/**
# NAME
  psv-export - dump exports from an elf

# USAGE
  psv-export [NAMES.yml] <in.velf >exports.yml

*/
#include "yml.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#ifndef USAGE
#define USAGE "See man psv-export\n"
#endif

int main() {
	char*    modname = "SceAppMgr";
	char*    libname = "SceAppMgrForDriver";
	uint32_t ver = 2, fw = 360, modnid = 0xDBB29DB7, libnid = 0xDCE180F8;

	yml_db_line line = {
	    .yml_version  = ver,
	    .yml_firmware = fw,
	    .mod_name     = modname,
	    .mod_nid      = modnid,
	    .lib_name     = libname,
	    .lib_nid      = libnid,
	    .lib_kernel   = 1,
	    .exp_name     = "ksceAppMgrAcInstGetAcdirParam",
	    .exp_nid      = 0x474AABDF,
	};
	yml_emitter(STDOUT_FILENO, line);
	return 0;
}