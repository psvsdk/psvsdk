#ifndef VITA_EXPORT_H
#define VITA_EXPORT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
	const char *name;
	uint32_t nid;
} vita_export_symbol;

typedef struct {
	const char *name;
	int syscall;
	size_t function_n;
	vita_export_symbol **functions;
	size_t variable_n;
	vita_export_symbol **variables;
	uint32_t nid;
} vita_library_export;

typedef struct {
	char name[27];
	uint8_t ver_major;
	uint8_t ver_minor;
	uint16_t attributes;
	uint32_t nid;
	const char *start;
	const char *stop;
	const char *exit;
	size_t module_n;
	vita_library_export **modules;
} vita_export_t;

#endif // VITA_EXPORT_H
