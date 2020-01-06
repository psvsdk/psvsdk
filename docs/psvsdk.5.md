[![PSVSDK](https://i.imgur.com/BOeAJIT.png?alternate=z31n9Rl)](https://github.com/psvsdk/psvsdk)

[![Travis](https://travis-ci.org/psvsdk/psvsdk.svg)](https://travis-ci.org/psvsdk/psvsdk)
[![CodeCov](https://img.shields.io/codecov/c/github/psvsdk/psvsdk.svg)](https://codecov.io/github/psvsdk/psvsdk)
[![Licence](https://img.shields.io/github/license/psvsdk/psvsdk.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/psvsdk/psvsdk.svg)](https://hub.docker.com/r/psvsdk/psvsdk)

Stable, clean and consistent SDK for the PSVita.

## Install

The easiest way to use the psvsdk is to `docker run -it psvsdk/psvsdk`.
This will give you an isolated development workspace.
Running in docker also allows the project to focus on a single codebase (no windows/macos subtilities)
If you don't want to remember this docker command, create an alias in your `.bash_aliases`:
`echo "alias psv-sh='docker run -it -v $HOME:/root psvsdk/psvsdk;docker container prune -f'" >> $HOME/.bash_aliases`

If you [don't like docker](https://thepracticaldev.s3.amazonaws.com/i/bkvr83xnp350khbetqcw.JPG),
feel free to [manually build](#manual-build--install) the vitasdk (spoiler: it's easy).

## Usage

The psvsdk provides a set of tools to compile your C sources into a PSVita compatible binary.
To do so, the following workflow is used:

![edit=s/svg/uml/](http://www.plantuml.com/plantuml/svg/PP3DQiCm48JlVWgXSoDeUnGfWHPAwG-bEOPGzBD9tCYIaUIGOlpkNJiIgidjs_5QipEh48MFNMCgNU-zQ0_ac_JLH1ilx57NVldsjUNMQTY4WsXXQPs5BQTjE2sqf3S9IAAzKeMoU0ApInZ-uSxbx-sHfjUbEszv5JfvkKQPBaJmjxqH4ioIFeC5Bo9e8Y9PFxsI5ui9ZA6SQib-6qCN3-aYf9uonj0ZA7YCtZ1nuG-8YCDmPNENRTv5RScdTp-W8kLz-Md-LeDhJD41FNDsn4d5cCWbVTRJaBie7_AG-yZwo3ptDIq8BngMXhnzdUK-PrbtiaIP7GJdrlauRusCQ6evDe0PIp92UQbX9XEAtapDHEHHH2F26CFpXce5LdUD-GC0)

### Main Project

- We first have a `main.c` file compiled with [psv-gcc](docs/psv-gcc.1.md) which is simply an ARM compiler with some pre-set flags.
- The produced arm-ELF is given to [psv-velf](docs/psv-velf.1.md) which adds some PSVita specific attributes.
- The generated Vita-ELF or `.velf` file is then given to [psv-self](docs/psv-self.1.md) which adds a signature and outputs a signed Elf `.self`.
- Finally the `.self` file is packaged, along with an SFO file (see later), into a VitaPacKage using [psv-vpk](docs/psv-vpk.1.md).
- The SFO file generated using [psv-sfo](docs/psv-sfo.1.md) is used to describe your application to the LiveArea (title, version, parental, ...).

### At install

- [psv-db](docs/psv-db.1.md) is used to search into the PSVita's libraries' functions.
- [psv-lib](docs/psv-lib.1.md) use this function list to generate a bunch of "stub" libraries.

This consistent naming is easy to remember and also easy to list using shell completion (`psv<TAB>`)

## Example
The psvsdk can be used without any build preprocessor

```sh
psv-gcc main.c -o a.elf
psv-velf a.elf | psv-self | psv-vpk | curl -T- ftp://$IP:1337/ux0:/my.vpk
```

Still, it can easily be tweaked to match any exotic requirements.

```sh
psv-gcc -nostdlib -lSceLibKernel_stub main.c -o a.elf &&
psv-velf --safe a.elf |
psv-self --authid=2 |
psv-vpk assets:data <(psv-sfo TITLE="Hello World" ATTRIBUTE=0x8000):sce_sys/param.sfo |
curl -T- ftp://$VITA_IP:1337/ux0:/tmp.vpk
```

## Manual Build & Install

This method requires the packages `build-essential` and `gcc-arm.`

- Build the toolchain using `make`. (see [Makefile](Makefile) for possible options)
- Install the toolchain with `sudo make install`
- Docker image can be built using `docker build -t psvsdk/psvsdk:latest .`

Feel free to take a look at the [.travis.yml](.travis.yml) or the [Dockerfile](Dockerfile) to see how the prebuild SDK is made.

## Requirements
psvsdk relies on the *PS Vita Open SDK specification* as defined by Yifan Lu, with additional enforcement:
- Portable and reproducible SDK building (Qemu/Docker could be useful)
- All commands/formats must be documented in their respective headers (sfo.h, yml.h, zip.h ...).

## Naming
- ELF: Executable Locatable File[3].
- Module : An (ELF) file that exports/provides 1-N libraries and imports/requires 0-N libraries.
- Library : A set of functions related to a common topic (Ctrl,Io,Thread ...).
- NameID (NID): 32-bit hash generated from a {module, library, symbol} name.
- VELF: Generic ARM ELF with Vita-specific sections `.sceModuleInfo.rodata` and Import/Export definitions.
- SELF: VELF with a signature header, a.k.a. Fake SELF (FSELF) if the signature is empty/unused.
- Stub: Piece of code that feign a function, so the code can compile, but in real life, this function will only be available at runtime.


