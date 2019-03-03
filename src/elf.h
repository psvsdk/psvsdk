#ifndef ELF_H
#define ELF_H
#include <stdint.h>
#include <stdlib.h>

enum {                     // e_ident
	EI_MAG0       = 0, // File identification index.
	EI_MAG1       = 1, // File identification index.
	EI_MAG2       = 2, // File identification index.
	EI_MAG3       = 3, // File identification index.
	EI_CLASS      = 4, // File class.
	EI_DATA       = 5, // Data encoding.
	EI_VERSION    = 6, // File version.
	EI_OSABI      = 7, // OS/ABI identification.
	EI_ABIVERSION = 8, // ABI version.
	EI_PAD        = 9, // Start of padding bytes.
	EI_NIDENT     = 16 // Number of bytes in e_ident.
};
enum {                // e_machine
	EM_NONE = 0,  // No machine
	EM_ARM  = 40, // ARM
};
enum { // e_ident[4]
	ELFCLASSNONE = 0,
	ELFCLASS32   = 1, // 32-bit object file
	ELFCLASS64   = 2  // 64-bit object file
};
enum {                   // e_ident[5]
	ELFDATANONE = 0, // Invalid data encoding.
	ELFDATA2LSB = 1, // Little-endian object file
	ELFDATA2MSB = 2  // Big-endian object file
};

typedef struct {
	uint8_t  e_ident[EI_NIDENT]; // ELF Identification bytes {-- -- -- -- 01 01 01 -- -- -- -- -- -- -- -- --}
	uint16_t e_type;             // Type of file (see ET_*) {0xfe14} / unused
	uint16_t e_machine;          // Required architecture for this file (see EM_*) {0x0028} / unused
	uint32_t e_version;          // Must be equal to 1 {0x00000001} / unused
	uint32_t e_entry;            // Address to jump to in order to start program {00 00 80 90} / unused
	uint32_t e_phoff;            // Program header table's file offset, in bytes (checked / unused)
	uint32_t e_shoff;            // Section header table's file offset, in bytes (unused / unused)
	uint32_t e_flags;            // Processor-specific flags (unused / unused)
	uint16_t e_ehsize;           // Size of ELF header, in bytes (0x0034 / unused)
	uint16_t e_phentsize;        // Size of an entry in the program header table (0x0020 / unused)
	uint16_t e_phnum;            // Number of entries in the program header table (0x0003 / unused)
	uint16_t e_shentsize;        // Size of an entry in the section header table (unused)
	uint16_t e_shnum;            // Number of entries in the section header table (checked / unused)
	uint16_t e_shstrndx;         // Sect hdr table index of sect name string table (unused)
} Elf32_Ehdr;

enum { // p_type
	PT_NULL    = 0,
	PT_LOAD    = 1,
	PT_DYNAMIC = 2,
	PT_INTERP  = 3,
	PT_NOTE    = 4,
	PT_SHLIB   = 5,
	PT_PHDR    = 6,
	PT_LOPROC  = 0x70000000,
	PT_HIPROC  = 0x7fffffff
};
typedef struct {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
} Elf32_Phdr;

// SECTION
enum { SHT_NULL          = 0,          // No associated section (inactive entry).
       SHT_PROGBITS      = 1,          // Program-defined contents.
       SHT_SYMTAB        = 2,          // Symbol table.
       SHT_STRTAB        = 3,          // String table.
       SHT_RELA          = 4,          // Relocation entries; explicit addends.
       SHT_HASH          = 5,          // Symbol hash table.
       SHT_DYNAMIC       = 6,          // Information for dynamic linking.
       SHT_NOTE          = 7,          // Information about the file.
       SHT_NOBITS        = 8,          // Data occupies no space in the file.
       SHT_REL           = 9,          // Relocation entries; no explicit addends.
       SHT_SHLIB         = 10,         // Reserved.
       SHT_DYNSYM        = 11,         // Symbol table.
       SHT_INIT_ARRAY    = 14,         // Pointers to initialization functions.
       SHT_FINI_ARRAY    = 15,         // Pointers to termination functions.
       SHT_PREINIT_ARRAY = 16,         // Pointers to pre-init functions.
       SHT_GROUP         = 17,         // Section group.
       SHT_SYMTAB_SHNDX  = 18,         // Indices for SHN_XINDEX entries.
       SHT_LOOS          = 0x60000000, // Lowest operating system-specific type.
       SHT_HIOS          = 0x6fffffff, // Highest operating system-specific type.
       SHT_LOPROC        = 0x70000000, // Lowest processor arch-specific type.
       SHT_HIPROC        = 0x7fffffff, // Highest processor arch-specific type.
       SHT_LOUSER        = 0x80000000, // Lowest type reserved for applications.
       SHT_HIUSER        = 0xffffffff  // Highest type reserved for applications.
};

/* sh_flags */
#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define SHF_MASKPROC 0xf0000000

/* special section indexes */
#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff

typedef struct {
	uint32_t sh_name;      // Section name (index into string table)
	uint32_t sh_type;      // Section type (SHT_*)
	uint32_t sh_flags;     // Section flags (SHF_*)
	uint32_t sh_addr;      // Address where section is to be loaded
	uint32_t sh_offset;    // File offset of section data, in bytes
	uint32_t sh_size;      // Size of section, in bytes
	uint32_t sh_link;      // Section type-specific header table index link
	uint32_t sh_info;      // Section type-specific extra information
	uint32_t sh_addralign; // Section address alignment
	uint32_t sh_entsize;   // Size of records contained within the section
} Elf32_Shdr;

typedef struct {
	uint32_t st_name;
	uint32_t st_value;
	uint32_t st_size;
	uint8_t  st_info;
	uint8_t  st_other;
	uint16_t st_shndx;
} Elf32_Sym;
#define ELF32_R_SYM(INFO) ((INFO) >> 8)
#define ELF32_R_TYPE(INFO) ((INFO)&0xFF)

enum { R_ARM_NONE            = 0,
       R_ARM_ABS32           = 2,
       R_ARM_REL32           = 3,
       R_ARM_THM_CALL        = 10,
       R_ARM_CALL            = 28,
       R_ARM_JUMP24          = 29,
       R_ARM_THM_JUMP24      = 30,
       R_ARM_TARGET1         = 38,
       R_ARM_V4BX            = 40,
       R_ARM_TARGET2         = 41,
       R_ARM_PREL31          = 42,
       R_ARM_MOVW_ABS_NC     = 43,
       R_ARM_MOVT_ABS        = 44,
       R_ARM_THM_MOVW_ABS_NC = 47,
       R_ARM_THM_MOVT_ABS    = 48,
       R_ARM_THM_PC11        = 102 };
typedef struct {
	uint32_t r_offset;
	// uint32_t r_info;
	uint32_t r_sym : 24; // MSB
	uint32_t r_type : 8; // LSB
} Elf32_Rel;

typedef struct {
	uint32_t r_offset;
	uint32_t r_info;
	uint32_t r_addend;
} Elf32_Rela;

#define elf_phdr(ehdr, i...) ((Elf32_Phdr*)(((uint8_t*)(ehdr)) + (ehdr)->e_phoff + (i - 0) * (ehdr)->e_phentsize))
#define elf_shdr(ehdr, i...) ((Elf32_Shdr*)(((uint8_t*)(ehdr)) + (ehdr)->e_shoff + (i - 0) * (ehdr)->e_shentsize))
#define elf_sdata(ehdr, shdr) (uint8_t*)(((uint8_t*)(ehdr)) + (shdr)->sh_offset)
#define elf_sname(ehdr, shdr) (char*)(((uint8_t*)(ehdr)) + elf_shdr(ehdr, (ehdr)->e_shstrndx)->sh_offset + (shdr)->sh_name)

#endif