[![PSVSDK](https://i.imgur.com/BOeAJIT.png?alternate=z31n9Rl)](https://github.com/psvsdk/psvsdk)

[![Travis](https://travis-ci.org/psvsdk/psvsdk.svg)](https://travis-ci.org/psvsdk/psvsdk)
[![CodeCov](https://img.shields.io/codecov/c/github/psvsdk/psvsdk.svg)](https://codecov.io/github/psvsdk/psvsdk)
[![Licence](https://img.shields.io/github/license/psvsdk/psvsdk.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/psvsdk/psvsdk.svg)](https://hub.docker.com/r/psvsdk/psvsdk)

Stable, clean and consistant SDK for the PSVita.

## Install

In order to get an isolated and easy upgradable dev envrionment,
the recommended way to use the psvsdk is to `docker pull psvsdk/psvsdk`.
This allow to maintain a clean codebase (no `#ifdef WIN32` ugliness)

However, feel free to manualy build it if you don't want to use/learn docker.

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
This consistant naming is easy to remember and also easy to list using shell completion (`psv<TAB>`)

```sh
psv-gcc  [OPTIONS...] sources...>out.elf # alias to arm-gcc with -D -I -L pre-set
psv-velf [OPTIONS...] <in.elf   >out.velf# convert ELF to a vita-eabi ELF
psv-self [OPTIONS...] <in.velf  >out.self# (Fake)Sign a VitaELF file
psv-sfo  [KEY=VAL...] [<in.sfo] >out.sfo # Create/Extend/Dump a System File Object
psv-vpk  [FILES[:zip]]<in.self  >out.vpk # Archive files into a VitaPacKage
psv-db   [OPTIONS...] <in.velf  >out.yml # Generate firmware libraries stubs
#TODO
psv-cl   [OPTIONS...] sources...>out.elf # alias to arm-clang with -D -I -L pre-set
psv-pkg  [FILES[:pkg_path]...]  >out.pkg # Archive files into a classic PKG
psv-core [OPTIONS...] <in.core  >out.log # Extract a psvita coredump file
psv-dasm [OPTIONS...] <in.velf  >out.asm # velf disasembler
```

KEY
:type
@koff
/voff
%limi
*size
=DATA

## Example
The psvsdk toolchain can be used without any build preprocessor

```sh
psv-cc main.c | psv-velf | psv-self | psv-vpk > out.vpk
```

Still, it can easily be tweaked to match any exotic requirements

```sh
psv-cc -nostdlib -lSceLibKernel_stub main.c |
psv-velf --safe |
psv-self --authid=2 |
psv-vpk assets:data <(psv-sfo TITLE="Hello World" ATTRIBUTE=+0x8000):sce_sys/param.sfo |
curl -T - ftp://$VITA_IP:1337/ux0:/tmp.vpk
```

[![](http://www.plantuml.com/plantuml/svg/PP3FQuCm5CVl_XNXdQUmxHZSQPUn3SPwB39UOhgwnYX9b1R9_xv76bEa9pzvyNr_fEr-BOv7ziEM8jBUeZcrdQq_lXjkXbRjtH57LPl1g8R3wEQo5V2GW16XxKifCx1qEIjzI7XmDvx74oH9CPmRNhX9N2D8FJclxEEYKIXT0tgsUtrdRyPvr1eujAAwz1hAbsHEj83oiaBIbjxg2ExYw1l2dV3JAlo9dM5VTlXJqWDVuiP6egSVAWc1d58veZYa7iIvNvwlXzmstwodN3wl4D-7V5v3xYPnoxWnLETni7xx52pB8kJKSKW6CJKFHVW7)](http://www.plantuml.com/plantuml/uml/PP3FQuCm5CVl_XNXdQUmxHZSQPUn3SPwB39UOhgwnYX9b1R9_xv76bEa9pzvyNr_fEr-BOv7ziEM8jBUeZcrdQq_lXjkXbRjtH57LPl1g8R3wEQo5V2GW16XxKifCx1qEIjzI7XmDvx74oH9CPmRNhX9N2D8FJclxEEYKIXT0tgsUtrdRyPvr1eujAAwz1hAbsHEj83oiaBIbjxg2ExYw1l2dV3JAlo9dM5VTlXJqWDVuiP6egSVAWc1d58veZYa7iIvNvwlXzmstwodN3wl4D-7V5v3xYPnoxWnLETni7xx52pB8kJKSKW6CJKFHVW7)

## Requirements
psvsdk rely on the *PS Vita Open SDK specification* as defined by Yifan Lu, with additionals enforcement:
- Portable and reproductible SDK building (Qemu/Docker could be usefull)
- All commands/formats must be documented in they respectiv headers (sfo.h, yml.h, zip.h ...).

## Naming
- ELF: Executable Locatable File[3].
- Module : An ELF that provide 1 or more Libraries (for exemple the  SceKernelThreadMgr Module provide SceThreadmgr,SceDebugLed,SceCpu...)
- Library : A set of functions related to a common topic (Ctrl,Io,Thread ...).
- NameID (NID): A 32 bits hash generated from a {module, library, symbol} name.
- VELF: ELF with Vita specific attributs :
  - A `.sceModuleInfo.rodata` section located in the same program segment as `.text`. It offsets fields are `{uint32_t seg_idx:2, seg_off:30;}`
  - Plateform specific Imports/Exports definition.
  - Dynamic linking informations stored as part of the import/export sections (SHT PROGBITS)
- FSELF: A (V)ELF Overhead that define the permission.

## Refinement

List of encoutered issues (✖) in VitaSDK, and they solutions (✔) in psvsdk.

✖ No SDK versioning => no possible evolutions for newer firmware/toolchain  
✔ Freeze the while vita build environement (tools+headers) using a **tagged** docker image

✖ No functional tests => possible regression on code changes/fix  
✔ Enforce checking at CI level against "golden" files

✖ Require you to compile a vanilla arm-gcc just to define some default flags(`-D__vita__`)  
✔ Wrap the official ARM GCC to add the required flags (see `psv-gcc`)

✖ Required dependencies (libelf) may conflict with your host  
✔ Build in a docker to get an isolated build environement

✖ Can only be (officialy) usable with a CMake wrapper  
✔ Keep you free to use any build process (shell, makefile, cmake...)

✖ Heterogeneous toolchain naming (`vita-pack-vpk`, `vita-elf-create` ...)?  
✔ All binaries follow the `psv-$type` format (`psv-sfo`, `psv-velf` ...)

✖ No manual included for offline use  
✔ All tools and formats have a manual (see `man psv-sfo` or `man sfo`)

✖ Heterogeneous source (error using `goto`, `return 0`, `return -N`)  
✔ Enforce formating rule at CI level

✖ Plateform specific issues (OSX, Windows)  
✔ Use docker as common platform for any host OS

