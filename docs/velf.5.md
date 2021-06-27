# NAME
velf - Vita-specific ELF

# DESCRIPTION

A velf provide the following additional informations:
- import: variable and function that hav been stubed with ARM code at build time
- export: variable and function stubs declaration that will be resolved at ELF loading.
- relocations: vita-compatible relocation list of variable and function

# VELF LAYOUT OVERVIEW

	ELF Header:
	- Class: ELF32
	- Data: LitleEndian
	- Machine: ARM
	- Flags: 0x5000400 (EABI.v5 | HardFloat)
	...
	- Type: 0xfe04 (SCE_RELEXEC)
	- EntryPoint: 0x2a10 (sceModule VAddress, see bellow)
	Program Headers:
	- Read + Executable segment:
		- text: the main executable payload
		- stubs: bouncer to the external function
		- sceModule: refered by elf EntryPoint
	- Read + Write segment:
		- .data
	- SCE_RELA segment (not loaded in RAM)
		- relocation info for functions + variables
	Section Headers are not used

# RELOCATION

As opposed to static executable wich can only be run from a specific address,
relocatable ELF can be executed from any address, wich is handy if you want to
load multiple program at the same times. But in order to do that, the loader
must know which symbols/addresses needs to be adapted to this given addresse
using a relocation table.

In VELF, this table found as the last program segment (0x10-aligned no RWX)

This table can define either long or short relocation entries.
The (default) long relocation entries cover a larger scope of symbol offset.

# MODULE INFO

In VELF, this struct is given by the ELF Header EntryPoint attribut.
It defines the current module information that are required to be loaded:
The module name, type, entrypoint, imports, exports, SDK version ...

# IMPORT/EXPORT

When linking to a *_stub libraries, it library fake the existence of the
required fonction/variable in order to compile and instead, setup a section
that contain all the required information for psv-velf to organize them into
an "import" list that the PSVita loader will understand and resolve so your
application will seemlessly be able to call external functions.

# CREDIT

based on the vitasdk vita-elf-create source:
https://github.com/vitasdk/vita-toolchain/

