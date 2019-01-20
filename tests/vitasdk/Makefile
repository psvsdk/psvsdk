# VitaSDK golden files rules
# (one shall rerun+commit them upon vitasdk update)
# $(shell grep -o '^tests/[^:]*' $(MAKEFILE_LIST))
base.sfo:
	vita-mksfoex ABCD99999 $@
title.sfo:
	vita-mksfoex SOMELONGTITLE $@
add_digit.sfo:
	vita-mksfoex ABCD99999 -d NEWVAL=123 $@
add_string.sfo:
	vita-mksfoex ABCD99999 -s NEWVAL=FooBar $@
replace_digit.sfo:
	vita-mksfoex ABCD99999 -d ATTRIBUTE=123 $@
replace_string.sfo:
	vita-mksfoex ABCD99999 -s BOOT_FILE=foo.bar $@
main_deps.elf:
	printf '#include <vitasdk.h>\nint mybss[4],myData[4]={1,2,3,4};\n void _start() __attribute__ ((weak, alias ("module_start")));int module_start(void){sceKernelDelayThread(1000);return sceKernelExitProcess(sceKernelGetThreadId());}' | arm-vita-eabi-gcc -nostdlib -Wl,-q -xc - -lSceLibKernel_stub -lSceKernelThreadMgr_stub -o $@
main_no_deps.elf:
	printf "void _start() __attribute__ ((weak, alias (\"module_start\")));int module_start(void){return 0;}" | arm-vita-eabi-gcc -nostdlib -xc - -o $@
