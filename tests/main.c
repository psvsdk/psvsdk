#include <vitasdk.h>
int mybss[4],myData[4]={1,2,3,4};
void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(void) {
	sceKernelDelayThread(1000);
	return sceKernelExitProcess(sceKernelGetThreadId());
}