/**
# NAME
  psv-sfo - Generate a System File Object

# SYNOPSIS
  Usage: %s [HOSTPATH[:VPKPATH]]... <in.self >out.vpk
    Generate a VPK with the given HOSTPATH files

  psv-sfo < in.sfo
    Dump given in.sfo

  psv-sfo
    Show the help screen

# EXAMPLES
  psv-sfo TITLE=MyGame ATTRIBUTE=+0xFF > param.sfo

# SEE ALSO
  - sfo(5)




FILES
	Can ba a regular file or a folder
	in wish case will be recursivelly archived

EXAMPLES
	outname.txt:inname.txt
	contrib/vita:contrib
	param.sfo:/sce_sys/param.sfo

NOTES
	A basic /sce_sys/param.sfo will be injected if none given

dd if=/dev/random of=big.img bs=4k iflag=fullblock,count_bytes count=1G

time psv-vpk _param.sfo:sce_sys/param.sfo big.img <main.self >out2.vpk
real	0m5.979s
user	0m0.009s
sys	0m1.824s

time vita-pack-vpk -s _param.sfo -b main.self -a big.img=big.img out2.vpk
real	0m51.453s
user	0m50.016s
sys	0m1.392s
*/
#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sfo.h"
#include "vpk.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#define countof(array) (sizeof(array) / sizeof(*(array)))
#define USAGE \
	"Usage: %s [HOSTPATH[:VPKPATH]]... <in.self >out.vpk\n\n\
FILES\n	Can ba a regular file or a folder\n	in wish case will be recursivelly archived\n\
EXAMPLES\n	outname.txt:inname.txt\n	contrib/vita:contrib\n	param.sfo:/sce_sys/param.sfo\n\
NOTES\n	A basic /sce_sys/param.sfo will be injected if none given\n"

#define VPK_PATH_SFO "sce_sys/param.sfo"
#define VPK_PATH_BIN "eboot.bin"
#define VPK_FIFO_LEN 32

typedef struct {
	ssize_t size, pos;
	char    buf[4096];
} psv_vpksfo_t;

/*psv_entry_t sfo_default[] = {
 {"STITLE", 6, "STITLE"},
 {"TITLE", 5, "TITLE"},
 {"TITLE_ID", 9, "ABCD99999"},
 {"APP_VER", 5, "01.00"},
 {"CATEGORY", 2, "gd"},
 {"PSP2_SYSTEM_VER", 0x00000000},
};*/


static void read_fifo(int fd, size_t * len, void** buf) {
	for (ssize_t ret = VPK_FIFO_LEN; ret == VPK_FIFO_LEN; *len += (ret = read(fd, *buf + *len, VPK_FIFO_LEN))) {
		*buf = realloc(*buf, *len + VPK_FIFO_LEN);
	}
}
static ssize_t inmem_sfo_emiter(void* fd, const void* buf, size_t len) {
	psv_vpksfo_t* sfo = (psv_vpksfo_t*)fd;
	if (sfo) {
		memcpy(sfo->buf + sfo->pos, buf, len);
		sfo->pos += len;
	}
	return len;
}

static int add_file_vpk(vpk_t* vpk, const char* src, const char* dst, int* found_sfo) {
	struct stat s;
	if (stat(src, &s)) {
		return 0;
	}
	*found_sfo |= !strcmp(dst, VPK_PATH_SFO);
	if (S_ISDIR(s.st_mode)) {
		vpkDir(vpk, dst);
		DIR* dir = opendir(src);
		for (struct dirent* entry; (entry = readdir(dir));) {
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;
			char src_dir[VPK_MAX_PATH];
			char dst_dir[VPK_MAX_PATH];
			snprintf(src_dir, sizeof(src_dir), "%s%s%s", src, src[strlen(src) - 1] == '/' ? "" : "/", entry->d_name);
			snprintf(dst_dir, sizeof(dst_dir), "%s%s%s", dst, dst[strlen(dst) - 1] == '/' ? "" : "/", entry->d_name);
			add_file_vpk(vpk, src_dir, dst_dir, found_sfo);
		}
		closedir(dir);
	} else if (S_ISREG(s.st_mode)) {
		char    buf[64*1024];
		ssize_t size = 0;
		int     fd = open(src, O_RDONLY);
		struct stat st;
		stat(src, &st);
		vpk_entry_t* file = vpkFileOpen(vpk, dst, (uint32_t) st.st_size);
		while ((size = read(fd, &buf, sizeof(buf))) > 0) {
			vpkFileWrite(file, buf, (size_t) size);
		}
		close(fd);
	} else if (S_ISFIFO(s.st_mode)) {
		void* fifo_ptr  = NULL;
		size_t fifo_len = 0;
		int   fd = open(src, O_RDONLY);
		read_fifo(fd, &fifo_len, &fifo_ptr);
		vpkFileWrite(vpkFileOpen(vpk, dst, (uint32_t) fifo_len), fifo_ptr, fifo_len);
		free(fifo_ptr);
		close(fd);
	} else { // symlink etc.
		return 0;
	}
	return 1;
}

int main(int argc, char** argv) {
	EXPECT(!isatty(STDOUT_FILENO) && !isatty(STDIN_FILENO), USAGE, argv[0]);
	vpk_t vpk = {STDOUT_FILENO, 0, 0, {}};

	void* self_ptr = NULL;
	size_t  self_len = 0;

	read_fifo(STDIN_FILENO, &self_len, &self_ptr);
	vpkFileWrite(vpkFileOpen(&vpk, VPK_PATH_BIN, (uint32_t) self_len), self_ptr, self_len);
	free(self_ptr);

	int has_sfo = 0;
	for (char *inpath, **path = argv + 1; path < argv + argc; path++) {
		strtok_r(*path, ":", &inpath);
		add_file_vpk(&vpk, *path, *inpath ? inpath : *path, &has_sfo);
	}

	if (!has_sfo) {/*
		char dir[1024], *t = (strrchr(getcwd(dir, sizeof(dir)-6),'/')?:"/ABCD12345")+1;
		sfo_default[0].val_s = sfo_default[1].val_s = t;
		sfo_default[0].val_i = sfo_default[1].val_i = (uint32_t) (strlen(t) + 1);
		sfo_default[2].val_s = (char[]){'P','S','D','K', '0'+(t[0]%10), '0'+(t[1]%10), '0'+(t[2]%10), '0'+(t[3]%10), '0'+(t[4]%10),0};
		fprintf(stderr,"%s;%s;%s\n", sfo_default[0].val_s, sfo_default[1].val_s, sfo_default[2].val_s);
		psv_vpksfo_t sfo = {};
		sfo.size = psv_sfo_emit(sfo_default, sfo_default + countof(sfo_default), inmem_sfo_emiter, &sfo);
		EXPECT(sfo.size <= (signed)sizeof(sfo.buf), "Fake SFO size too big (>%zu)", sizeof(sfo.buf));
		psv_sfo_emit(sfo_default, sfo_default + countof(sfo_default), inmem_sfo_emiter, &sfo);
		vpkFileWrite(vpkFileOpen(&vpk, VPK_PATH_SFO, (uint32_t) sfo.size), sfo.buf, (size_t) sfo.size);*/
	}

	return vpkClose(&vpk);
}