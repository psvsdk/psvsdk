/**
# NAME

psv-vpk - Generate a Vita PacKage

# SYNOPSIS

    psv-vpk [HOST_PATH[:VPK_PATH]]... > out.vpk

# OPTIONS

  - HOST_PATH: path on the host filesystem (file or folder)
  - VPK_PATH:  path inside the package (HOST_PATH if no given)

# EXAMPLES

    psv-vpk app.sfo:sce_sys/param.sfo app.self:eboot.bin

# NOTES

Generated archive won't have CRCs (unused by the installer)
This can be seen as an issue from regular archive manager.
You can still extract them using: `unzip -od. no-crc.vpk`

# SEE ALSO
  - vpk(5)
*/
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vpk.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#define DEBUG(FMT, ...)      \
	if (getenv("DEBUG")) \
		fprintf(stderr, FMT "\n", __VA_ARGS__);
#ifndef USAGE
#define USAGE "See man psv-vpk\n"
#endif
#define ALIGN(V) (((V) + ((4) - 1)) & ~((4) - 1))

#define VPK_PATH_SFO "sce_sys/param.sfo"
#define VPK_PATH_BIN "eboot.bin"

static int add_file_vpk(vpk_t* vpk, const char* src, const char* dst, bool* found_sfo, bool* found_bin) {
	struct stat s;
	EXPECT(!stat(src, &s), "Unable to stat %s", src);
	*found_sfo |= !strcmp(dst, VPK_PATH_SFO);
	*found_bin |= !strcmp(dst, VPK_PATH_BIN);
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
			add_file_vpk(vpk, src_dir, dst_dir, found_sfo, found_bin);
		}
		closedir(dir);
	} else if (S_ISREG(s.st_mode)) {
		char         buf[PIPE_BUF];
		int          fd   = open(src, O_RDONLY);
		vpk_entry_t* file = vpkFileOpen(vpk, dst, (uint32_t)s.st_size);
		for (ssize_t size = 0; (size = read(fd, &buf, sizeof(buf))) > 0;) {
			vpkFileWrite(file, buf, size);
		}
		close(fd);
	} else { // symlink etc. => skip as it can be from a recursiv directory
		DEBUG("%s is not a regular file/directory => skip", src);
		return 0;
	}
	return 0;
}

int main(int argc, char** argv) {
	EXPECT(!isatty(STDOUT_FILENO), "%s", USAGE);
	vpk_t vpk = {STDOUT_FILENO, 0, 0, {}};

	bool has_sfo = false, has_bin = false;

	for (char *inpath, **path = argv + 1; path < argv + argc; path++) {
		strtok_r(*path, ":", &inpath);
		add_file_vpk(&vpk, *path, *inpath ? inpath : *path, &has_sfo, &has_bin);
	}

	EXPECT(has_bin, VPK_PATH_BIN " not given");
	EXPECT(has_sfo, VPK_PATH_SFO " not given");

	return vpkClose(&vpk);
}