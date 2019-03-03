/**
# NAME
  psv-vpk - Generate a Vita PacKage

# SYNOPSIS
	psv-vpk [HOST_PATH[:VPK_PATH]]... [<in.self] >out.vpk

# OPTIONS
 - HOST_PATH: path on the host filesystem (file or folder)
 - VPK_PATH:  path inside the package (HOST_PATH if no given)

# EXAMPLES

	psv-vpk < a.self
	psv-vpk sce_sys assets:data a.self:eboot.bin
	psv-vpk <(psv-sfo TITLE="Hello World" ...):sce_sys/param.sfo < a.self

# NOTES

  Archived files will have they CRC field unset (because unchecked during unpacking)
  To extract VPK simply unzip it using: `unzip -od. *.vpk` (ignore bad CRC warning)

# SEE ALSO
  - vpk(5)
*/
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

#include "self.h"
#include "sfo.h"
#include "vpk.h"

#define EXPECT(EXPR, FMT, ...) \
	if (!(EXPR))           \
		return fprintf(stderr, FMT "\n", ##__VA_ARGS__), -1;
#define DEBUG(FMT, ...) getenv("DEBUG") && fprintf(stderr, FMT "\n", __VA_ARGS__);
#ifndef USAGE
#define USAGE "See man psv-vpk\n"
#endif
#define countof(array) (sizeof(array) / sizeof(*(array)))
#define ALIGN(V) (((V) + ((4) - 1)) & ~((4) - 1))

#define VPK_PATH_SFO "sce_sys/param.sfo"
#define VPK_PATH_BIN "eboot.bin"

static int add_file_vpk(vpk_t* vpk, const char* src, const char* dst, bool* found_sfo, bool* found_bin) {
	struct stat s;
	if (stat(src, &s)) {
		return 0;
	}
	*found_sfo |= !strcmp(dst, VPK_PATH_SFO);
	*found_bin |= !strcmp(dst, VPK_PATH_BIN);
	char buf[PIPE_BUF];
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
		int         fd = open(src, O_RDONLY);
		struct stat st;
		stat(src, &st);
		vpk_entry_t* file = vpkFileOpen(vpk, dst, (uint32_t)st.st_size);
		for (ssize_t size = 0; (size = read(fd, &buf, sizeof(buf))) > 0;) {
			vpkFileWrite(file, buf, size);
		}
		close(fd);
	} else if (S_ISFIFO(s.st_mode)) {
		int     fd  = open(src, O_RDONLY);
		ssize_t len = read(fd, buf, sizeof(buf));
		EXPECT(len < sizeof(buf), "too large piping");
		vpkFileWrite(vpkFileOpen(vpk, dst, (uint32_t)len), buf, len);
		close(fd);
	} else { // symlink etc.
		DEBUG("%s is not a regular file => skip", src);
		return 0;
	}
	return 1;
}

int main(int argc, char** argv) {
	EXPECT(!isatty(STDOUT_FILENO), "%s", USAGE);
	vpk_t vpk = {STDOUT_FILENO, 0, 0, {}};

	bool has_sfo = false, has_bin = false;

	for (char *inpath, **path = argv + 1; path < argv + argc; path++) {
		strtok_r(*path, ":", &inpath);
		add_file_vpk(&vpk, *path, *inpath ? inpath : *path, &has_sfo, &has_bin);
	}

	if (!isatty(STDIN_FILENO)) {
		char        buf[PIPE_BUF];
		SELF_header self_header;
		EXPECT(read(STDIN_FILENO, &self_header, sizeof(self_header)) == sizeof(self_header), "SELF too small");
		EXPECT(self_header.magic == SELF_HEADER_MAGIC, "stdin is not a SELF");
		vpk_entry_t* bin_entry = vpkFileOpen(&vpk, VPK_PATH_BIN, (uint32_t)self_header.self_filesize);
		vpkFileWrite(bin_entry, &self_header, sizeof(self_header));
		for (uint32_t r = 0, done = sizeof(self_header); done < self_header.self_filesize; done += r) {
			r = (uint32_t)vpkFileWrite(bin_entry, &buf, read(STDIN_FILENO, &buf, sizeof(buf)));
		}
		has_bin = true;
	}

	EXPECT(has_bin, VPK_PATH_BIN " not received (via args or stdin)");

	if (!has_sfo) {
		char  dir[PATH_MAX];
		char* title = (strrchr(getcwd(dir, sizeof(dir) - 6), '/') ?: "/ABCD12345") + 1;
#define ID(C) ((char)('0' + ((C) % 10)))
		char* id = (char[]){'P', 'S', 'D', 'K', ID(title[0]), ID(title[1]), ID(title[2]), ID(title[3]), ID(title[4]), 0};
#undef ID
		char* keys[] = {"APP_VER", "ATTRIBUTE", "CATEGORY", "PSP2_SYSTEM_VER", "STITLE", "TITLE", "TITLE_ID"};
		char* vals[] = {"00.00", "0x0", "gd", "0x0", title, title, id};

		sfo_entry_t entries[sizeof(vals)];
		memset(entries, -1, sizeof(entries));
		psv_sfo_hydrate(countof(keys), keys, vals, entries);
		ssize_t sfo_size = psv_sfo_emit(countof(keys), keys, vals, entries, NULL, NULL);
		DEBUG("Generated (S)TITLE:%s [%s]", title, id);
		vpk_entry_t* sfo_file = vpkFileOpen(&vpk, VPK_PATH_SFO, (uint32_t)sfo_size);
		psv_sfo_emit(countof(keys), keys, vals, entries, (sfo_emitter_t)vpkFileWrite, sfo_file);
	}

	return vpkClose(&vpk);
}