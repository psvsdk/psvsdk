[![PSVSDK](https://i.imgur.com/BOeAJIT.png?alternate=z31n9Rl)](https://github.com/psvsdk/psvsdk)

[![Travis](https://travis-ci.org/psvsdk/psvsdk.svg)](https://travis-ci.org/psvsdk/psvsdk)
[![CodeCov](https://img.shields.io/codecov/c/github/psvsdk/psvsdk.svg)](https://codecov.io/github/psvsdk/psvsdk)
[![Licence](https://img.shields.io/github/license/psvsdk/psvsdk.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/psvsdk/psvsdk.svg)](https://hub.docker.com/r/psvsdk/psvsdk)

Stable, clean and consistent SDK for the PSVita.

## Install

In order to get an isolated and easy upgradable dev environment,
the recommended way to use the psvsdk is to `docker pull psvsdk/psvsdk`.
This allow to maintain a clean codebase (no `#ifdef WIN32` ugliness)

However, feel free to manually build it if you don't want to use/learn docker.

## Manual Build & Install

*This method require you to install gcc + make + gcc-arm.*

- To build the toolchain: `make`. (see [Makefile](Makefile) for possible options)
- To install the toolchain: `sudo make install`
- To build a single `psv` binary: `cc psv-acme.c`
- To install a single `psv`, just cp it onto one of your `$PATH` directories (see `echo $PATH`)
- To build a docker image: `docker build -t psvsdk/psvsdk:latest .`

Feel free to take a look at the [.travis.yml](.travis.yml) or the [Dockerfile](Dockerfile) to see how the toolchain is built.

## Usage
Every binaries follow the `psv-${outformat}` naming.
This consistent naming is easy to remember and also easy to list using shell completion (`psv<TAB>`)

```sh
psv-gcc  [OPTIONS...] sources...>out.elf  # alias to arm-gcc with -D -I -L pre-set
psv-velf [OPTIONS...] <in.elf   >out.velf # convert ELF to a vita-eabi ELF
psv-self [OPTIONS...] <in.velf  >out.self # (Fake)Sign a VitaELF file
psv-sfo  [KEY=VAL...][<in.sfo] [>out.sfo] # Create/Extend/Dump a System File Object
psv-vpk  [FILE[:zip]...]<in.self  >out.vpk  # Archive files into a VitaPacKage
psv-db   [OPTIONS...] <in.velf  >out.yml  # Generate firmware libraries stubs
```

```
#TODO
psv-cl   [OPTIONS...] sources...>out.elf # alias to arm-clang with -D -I -L pre-set
psv-pkg  [FILES[:pkg_path]...]  >out.pkg # Archive files into a classic PKG
psv-core [OPTIONS...] <in.core  >out.log # Extract a psvita coredump file
psv-dasm [OPTIONS...] <in.velf  >out.asm # velf disasembler
```

## Example
The psvsdk toolchain can be used without any build preprocessor

```sh
psv-gcc main.c | psv-velf | psv-self | psv-vpk > out.vpk
```

Still, it can easily be tweaked to match any exotic requirements

```sh
psv-gcc -nostdlib -lSceLibKernel_stub main.c |
psv-velf --safe |
psv-self --authid=2 |
psv-vpk assets:data <(psv-sfo TITLE="Hello World" ATTRIBUTE=0x8000):sce_sys/param.sfo |
curl -T - ftp://$VITA_IP:1337/ux0:/tmp.vpk
```

[![edit=s/svg/uml/](http://www.plantuml.com/plantuml/svg/PP3DQiCm48JlVWgXSoDeUnGfWHPAwG-bEOPGzBD9tCYIaUIGOlpkNJiIgidjs_5QipEh48MFNMCgNU-zQ0_ac_JLH1ilx57NVldsjUNMQTY4WsXXQPs5BQTjE2sqf3S9IAAzKeMoU0ApInZ-uSxbx-sHfjUbEszv5JfvkKQPBaJmjxqH4ioIFeC5Bo9e8Y9PFxsI5ui9ZA6SQib-6qCN3-aYf9uonj0ZA7YCtZ1nuG-8YCDmPNENRTv5RScdTp-W8kLz-Md-LeDhJD41FNDsn4d5cCWbVTRJaBie7_AG-yZwo3ptDIq8BngMXhnzdUK-PrbtiaIP7GJdrlauRusCQ6evDe0PIp92UQbX9XEAtapDHEHHH2F26CFpXce5LdUD-GC0)

## Requirements
psvsdk rely on the *PS Vita Open SDK specification* as defined by Yifan Lu, with additional enforcement:
- Portable and reproducible SDK building (Qemu/Docker could be useful)
- All commands/formats must be documented in they respective headers (sfo.h, yml.h, zip.h ...).

## Naming
- ELF: Executable Locatable File[3].
- Module : An ELF that provide 1 or more Libraries (for example the  SceKernelThreadMgr Module provide SceThreadmgr,SceDebugLed,SceCpu...)
- Library : A set of functions related to a common topic (Ctrl,Io,Thread ...).
- NameID (NID): A 32 bits hash generated from a {module, library, symbol} name.
- VELF: ELF with Vita specific attributes :
  - A `.sceModuleInfo.rodata` section located in the same program segment as `.text`. It offsets fields are `{uint32_t seg_idx:2, seg_off:30;}`
  - Platform specific Imports/Exports definition.
  - Dynamic linking information stored as part of the import/export sections (SHT PROGBITS)
- FSELF: A (V)ELF Overhead that define the permission.

## Refinement

List of encountered issues (✖) in VitaSDK, and they solutions (✔) in psvsdk.

✖ No SDK versioning => no possible evolutions for newer firmware/toolchain  
✔ Freeze the while vita build environment (tools+headers) using a **tagged** docker image

✖ No functional tests => possible regression on code changes/fix  
✔ Enforce checking at CI level against "golden" files

✖ Require you to compile a vanilla arm-gcc just to define some default flags(`-D__vita__`)  
✔ Wrap the official ARM GCC to add the required flags (see `psv-gcc`)

✖ Required dependencies (libelf) may conflict with your host  
✔ Build in a docker to get an isolated build environment

✖ Can only be (officially) usable with a CMake wrapper  
✔ Keep you free to use any build process (shell, makefile, cmake...)

✖ Heterogeneous toolchain naming (`vita-pack-vpk`, `vita-elf-create` ...)?  
✔ All binaries follow the `psv-$type` format (`psv-sfo`, `psv-velf` ...)

✖ No manual included for offline use  
✔ All tools and formats have a manual (see `man psv-sfo` or `man sfo`)

✖ Heterogeneous source (error using `goto`, `return 0`, `return -N`)  
✔ Enforce formatting rule at CI level

✖ Platform specific issues (OSX, Windows)  
✔ Use docker as common platform for any host OS

