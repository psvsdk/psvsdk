/**
	YAML structure example

version: 2
firmware: 3.60
modules:
  SceAppMgr:
    nid: 0xDBB29DB7
    libraries:
    --SceAppMgrForDriver:
    ----kernel: true
    ----nid: 0xDCE180F8
    ----functions:
    ------ksceAppMgrAcInstGetAcdirParam: 0x474AABDF
    ------...
*/
#ifndef YML_H
#define YML_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define YML_MAX_LINE 128
#define YML_MAX_MODNAME 128
#define YML_MAX_LIBNAME 128
#define YML_MAX_EXPNAME 128
#define YML_MAX_NID 16

static char* yml_readline(int fd) {
	static char line[YML_MAX_LINE];
	for (int len = 0; read(fd, line + len, sizeof(*line)) > 0 && len < YML_MAX_LINE; len++) {
		if (line[len] == '\n') {
			line[len] = '\0';
			return line;
		}
	}
	return NULL;
}

static int yml_indent(char* str) {
	int n;
	for (n = 0; str[n] == ' '; n++)
		;
	return n;
}

typedef struct {
	uint32_t yml_version, yml_firmware;
	char*    mod_name;
	uint32_t mod_nid;
	char*    lib_name;
	uint32_t lib_nid, lib_kernel;
	char*    exp_name;
	uint32_t exp_nid;
} yml_db_line;

typedef void (*yml_walker_cb)(void*, yml_db_line);

void yml_emitter(int fd, yml_db_line line) {
	static yml_db_line accu = {};
	if (accu.yml_version != line.yml_version) {
		dprintf(fd, "version: %i\n", accu.yml_version = line.yml_version);
	}
	if (accu.yml_firmware != line.yml_firmware) {
		dprintf(fd, "firmware: %.2f\n", 0.01 * (accu.yml_firmware = line.yml_firmware));
	}
	if (!accu.mod_name && line.mod_name) {
		dprintf(fd, "modules:\n");
	}
	if (accu.mod_name != line.mod_name) {
		dprintf(fd, "  %s:\n", accu.mod_name = line.mod_name);
		accu.lib_name = NULL;
	}
	if (accu.mod_nid != line.mod_nid) {
		dprintf(fd, "    nid: 0x%08X\n", accu.mod_nid = line.mod_nid);
	}
	if (!accu.lib_name && line.lib_name) {
		dprintf(fd, "    libraries:\n");
	}
	if (accu.lib_name != line.lib_name) {
		dprintf(fd, "      %s:\n", accu.lib_name = line.lib_name);
		accu.exp_name = NULL;
	}
	if (accu.lib_kernel != line.lib_kernel) {
		dprintf(fd, "        kernel: %s\n", (accu.lib_kernel = line.lib_kernel) ? "true" : "false");
	}
	if (accu.lib_nid != line.lib_nid) {
		dprintf(fd, "        nid: 0x%08X\n", accu.lib_nid = line.lib_nid);
	}
	if (!accu.exp_name && line.exp_name) {
		dprintf(fd, "        functions:\n");
	}
	if (accu.exp_name != line.exp_name) {
		accu.exp_name = line.exp_name;
		accu.exp_nid  = 0;
	}
	if (accu.exp_nid != line.exp_nid) {
		dprintf(fd, "          %s: 0x%08X\n", accu.exp_name, accu.exp_nid = line.exp_nid);
	}
}
void yml_walker(int fd, yml_walker_cb cb, void* ctx) {
	char     mod_name[YML_MAX_MODNAME], lib_name[YML_MAX_LIBNAME], exp_name[YML_MAX_EXPNAME];
	uint32_t mod_nid, lib_nid, lib_kernel, exp_nid, yml_version, yml_firmware;
	for (char *line, *val; (line = yml_readline(fd));) {
		strtok_r(line, ":", &val);
		int i = yml_indent(line);
		line += i;
		if (i == 0 && !strcmp(line, "version")) {
			yml_version = atoi(val);
		} else if (i == 0 && !strcmp(line, "firmware")) {
			yml_firmware = atof(val) * 100;
		} else if (i == 2) {
			strncpy(mod_name, line, sizeof(mod_name));
		} else if (i == 4 && !strcmp(line, "nid")) {
			mod_nid = strtoul(val, NULL, 0);
			cb(ctx, (yml_db_line){yml_version, yml_firmware, mod_name, mod_nid});
		} else if (i == 6) {
			strncpy(lib_name, line, sizeof(lib_name));
		} else if (i == 8 && !strcmp(line, "kernel")) {
			lib_kernel = !!strstr(val, "true");
		} else if (i == 8 && !strcmp(line, "nid")) {
			lib_nid = strtoul(val, NULL, 0);
			cb(ctx,
			   (yml_db_line){yml_version, yml_firmware, mod_name, mod_nid, lib_name, lib_nid, lib_kernel});
		} else if (i == 10) {
			strncpy(exp_name, line, sizeof(exp_name));
			exp_nid = strtoul(val, NULL, 0);
			cb(ctx, (yml_db_line){yml_version, yml_firmware, mod_name, mod_nid, lib_name, lib_nid,
					      lib_kernel, exp_name, exp_nid});
		}
	}
	cb(ctx, (yml_db_line){});
}
#endif
