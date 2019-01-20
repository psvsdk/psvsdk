#include "yml.h"

#define EXPECT(EXPR, FMT, ...)                            \
	if (!(EXPR)) {                                    \
		fprintf(stderr, FMT "\n", ##__VA_ARGS__); \
		return -1;                                \
	}
#define USAGE \
	"Usage: %s [NAMES.yml] <in.velf >exports.yml\nNAMES.yml:\n\
MyModule:\n\
  attributes: 0\n\
  version:\n\
    major: 1\n\
    minor: 0\n\
  main:\n\
    start: module_start\n\
  libraries:\n\
    MyLib:\n\
      syscall: false\n\
      functions:\n\
        - ml_funcA\n"

int main() {

	char *   modname = "SceAppMgr", *libname = "SceAppMgrForDriver";
	uint32_t ver = 2, fw = 360, modnid = 0xDBB29DB7, libnid = 0xDCE180F8;
	yml_emitter(STDOUT_FILENO, (yml_db_line){
				       .yml_version  = ver,
				       .yml_firmware = fw,
				       .mod_name     = modname,
				       .mod_nid      = modnid,
				       .lib_name     = libname,
				       .lib_nid      = libnid,
				       .lib_kernel   = 1,
				       .exp_name     = "ksceAppMgrAcInstGetAcdirParam",
				       .exp_nid      = 0x474AABDF,
				   });
	yml_emitter(STDOUT_FILENO, (yml_db_line){
				       .yml_version  = ver,
				       .yml_firmware = fw,
				       .mod_name     = modname,
				       .mod_nid      = modnid,
				       .lib_name     = libname,
				       .lib_nid      = libnid,
				       .lib_kernel   = 1,
				       .exp_name     = "bidon",
				       .exp_nid      = 0xDEADBEEF,
				   });
	return 0;
}